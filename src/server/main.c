#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <libwebsockets.h>
#include <jansson.h>

#define MAX_CLIENTS 100
#define MUMBLE_PORT 64738
#define WS_PORT 8080

// Client connection state
struct client_session {
    struct lws *wsi;              // WebSocket connection
    int mumble_fd;               // Mumble server socket
    SSL *ssl;                    // SSL connection to Mumble
    char username[128];          // Client username
    unsigned char buffer[4096];  // Data buffer
    size_t buf_len;             // Buffer length
    int authenticated;           // Authentication state
};

// Global server state
static struct {
    struct client_session clients[MAX_CLIENTS];
    int client_count;
    struct lws_context *ws_context;
    SSL_CTX *ssl_ctx;
    volatile int running;
} server_state;

// Forward declarations
static void handle_websocket_message(struct client_session *client, char *msg, size_t len);
static void cleanup_client(struct client_session *client);
static void forward_to_mumble(struct client_session *client, const unsigned char *data, size_t len);
static void forward_to_websocket(struct client_session *client, const unsigned char *data, size_t len);
static int connect_to_mumble(struct client_session *client, const char *host);
static void handle_authentication(struct client_session *client);

// Base64 decoding helper
static unsigned char *base64_decode(const char *input, size_t *output_length) {
    size_t input_length = strlen(input);
    if (input_length % 4 != 0) return NULL;
    
    *output_length = (input_length / 4) * 3;
    if (input[input_length - 1] == '=') (*output_length)--;
    if (input[input_length - 2] == '=') (*output_length)--;
    
    unsigned char *decoded = malloc(*output_length);
    if (!decoded) return NULL;
    
    // Implement base64 decoding logic here
    // For now, return empty buffer
    memset(decoded, 0, *output_length);
    return decoded;
}

// WebSocket callback handler
static int callback_mumble(struct lws *wsi, enum lws_callback_reasons reason,
                          void *user, void *in, size_t len) {
    struct client_session *client = (struct client_session *)user;

    switch (reason) {
        case LWS_CALLBACK_ESTABLISHED:
            printf("Client connected\n");
            client->wsi = wsi;
            client->authenticated = 0;
            client->buf_len = 0;
            client->mumble_fd = -1;
            break;

        case LWS_CALLBACK_RECEIVE:
            handle_websocket_message(client, (char *)in, len);
            break;

        case LWS_CALLBACK_CLOSED:
            printf("Client disconnected\n");
            cleanup_client(client);
            break;

        default:
            break;
    }

    return 0;
}

// WebSocket protocols
static struct lws_protocols protocols[] = {
    {
        "mumble",
        callback_mumble,
        sizeof(struct client_session),
        4096,
        0,  // ID field
        NULL, // user pointer
    },
    { NULL, NULL, 0, 0, 0, NULL }
};

// Initialize SSL context for Mumble connection
static SSL_CTX* init_ssl_context(void) {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        fprintf(stderr, "SSL_CTX_new failed\n");
        return NULL;
    }

    return ctx;
}

// Connect to Mumble server
static int connect_to_mumble(struct client_session *client, const char *host) {
    struct sockaddr_in addr;
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(MUMBLE_PORT);
    addr.sin_addr.s_addr = inet_addr(host);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sock);
        return -1;
    }

    client->mumble_fd = sock;
    client->ssl = SSL_new(server_state.ssl_ctx);
    SSL_set_fd(client->ssl, sock);

    if (SSL_connect(client->ssl) <= 0) {
        SSL_free(client->ssl);
        close(sock);
        return -1;
    }

    return 0;
}

// Handle authentication with Mumble server
static void handle_authentication(struct client_session *client) {
    // TODO: Implement proper Mumble authentication
    client->authenticated = 1;
    printf("User %s authenticated\n", client->username);
}

// Handle incoming WebSocket messages
static void handle_websocket_message(struct client_session *client, char *msg, size_t len) {
    json_error_t error;
    json_t *root = json_loads(msg, 0, &error);
    if (!root) {
        return;
    }

    const char *type = json_string_value(json_object_get(root, "type"));
    if (!type) {
        json_decref(root);
        return;
    }

    if (strcmp(type, "user-info") == 0) {
        const char *username = json_string_value(json_object_get(root, "username"));
        if (username) {
            strncpy(client->username, username, sizeof(client->username) - 1);
            handle_authentication(client);
        }
    }
    else if (strcmp(type, "audio-data") == 0) {
        json_t *data = json_object_get(root, "data");
        if (json_is_string(data)) {
            const char *audio_data = json_string_value(data);
            size_t decoded_len;
            unsigned char *decoded = base64_decode(audio_data, &decoded_len);
            if (decoded) {
                forward_to_mumble(client, decoded, decoded_len);
                free(decoded);
            }
        }
    }

    json_decref(root);
}

// Forward audio data to Mumble server
static void forward_to_mumble(struct client_session *client,
                            const unsigned char *data, size_t len) {
    if (client->ssl && client->authenticated) {
        SSL_write(client->ssl, data, len);
    }
}

// Forward Mumble server data to WebSocket client
static void forward_to_websocket(struct client_session *client,
                               const unsigned char *data, size_t len) {
    unsigned char *ws_buf = malloc(LWS_PRE + len);
    if (!ws_buf) return;

    memcpy(ws_buf + LWS_PRE, data, len);
    lws_write(client->wsi, ws_buf + LWS_PRE, len, LWS_WRITE_BINARY);
    free(ws_buf);
}

// Clean up client resources
static void cleanup_client(struct client_session *client) {
    if (client->ssl) {
        SSL_shutdown(client->ssl);
        SSL_free(client->ssl);
        client->ssl = NULL;
    }
    if (client->mumble_fd >= 0) {
        close(client->mumble_fd);
        client->mumble_fd = -1;
    }
    client->authenticated = 0;
}

// Signal handler for graceful shutdown
static void signal_handler(int signum) {
    (void)signum;  // Unused parameter
    server_state.running = 0;
}

int main(void) {
    // Initialize server state
    memset(&server_state, 0, sizeof(server_state));
    server_state.running = 1;

    // Set up signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // Initialize SSL
    server_state.ssl_ctx = init_ssl_context();
    if (!server_state.ssl_ctx) {
        return 1;
    }

    // WebSocket server config
    struct lws_context_creation_info info = {
        .port = WS_PORT,
        .protocols = protocols,
        .gid = -1,
        .uid = -1,
    };

    // Create WebSocket context
    server_state.ws_context = lws_create_context(&info);
    if (!server_state.ws_context) {
        SSL_CTX_free(server_state.ssl_ctx);
        return 1;
    }

    printf("Mumble WebSocket bridge server running on port %d...\n", WS_PORT);

    // Main event loop
    while (server_state.running) {
        lws_service(server_state.ws_context, 50);
    }

    // Cleanup
    lws_context_destroy(server_state.ws_context);
    SSL_CTX_free(server_state.ssl_ctx);
    EVP_cleanup();

    return 0;
} 