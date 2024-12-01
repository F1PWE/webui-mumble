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
#include <arpa/inet.h>
#include <pthread.h>
#include <stdarg.h>
#include <errno.h>

// Debug logging function
static void debug_log(const char *format, ...) {
    va_list args;
    va_start(args, format);
    fprintf(stderr, "[DEBUG] ");
    vfprintf(stderr, format, args);
    fprintf(stderr, "\n");
    va_end(args);
}

// Error checking macros
#define CHECK_NULL(ptr, msg) \
    do { \
        if ((ptr) == NULL) { \
            debug_log("ERROR: %s", msg); \
            return -1; \
        } \
    } while(0)

#define CHECK_SSL(ret, msg) \
    do { \
        if ((ret) <= 0) { \
            debug_log("SSL ERROR: %s - %s", msg, ERR_error_string(ERR_get_error(), NULL)); \
            return -1; \
        } \
    } while(0)

#define CHECK_SOCKET(ret, msg) \
    do { \
        if ((ret) < 0) { \
            debug_log("SOCKET ERROR: %s - %s", msg, strerror(errno)); \
            return -1; \
        } \
    } while(0)

#define MAX_CLIENTS 100
#define MUMBLE_PORT 64738
#define WS_PORT 8080
#define DEFAULT_HOST "nimmerchat.xyz"
#define MUMBLE_VERSION_1 0x10203  // Mumble 1.2.3
#define MUMBLE_VERSION_2 0x10205  // Mumble 1.2.5

// Mumble message types
enum {
    Version = 0,
    Authenticate = 2,
    Ping = 3,
    UserState = 9,
    UserRemove = 10,
    ChannelState = 7,
    TextMessage = 11
};

// Mumble protocol packet
struct MumblePacket {
    uint16_t type;
    uint32_t length;
    unsigned char *payload;
};

// Client connection state
struct client_session {
    struct lws *wsi;              // WebSocket connection
    int mumble_fd;               // Mumble server socket
    SSL *ssl;                    // SSL connection to Mumble
    char username[128];          // Client username
    unsigned char buffer[4096];  // Data buffer
    size_t buf_len;             // Buffer length
    int authenticated;           // Authentication state
    char *server_host;          // Mumble server host
    uint32_t session;           // Mumble session ID
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
static void *mumble_receive_thread(void *arg);
static void handle_mumble_packet(struct client_session *client, const unsigned char *data, size_t len);
static int send_version_packet(struct client_session *client);
static int send_auth_packet(struct client_session *client);

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
            debug_log("WebSocket connection established");
            client->wsi = wsi;
            client->authenticated = 0;
            client->buf_len = 0;
            client->mumble_fd = -1;
            client->server_host = strdup(DEFAULT_HOST);
            if (!client->server_host) {
                debug_log("Failed to allocate server host");
                return -1;
            }
            break;

        case LWS_CALLBACK_RECEIVE:
            debug_log("WebSocket data received, length: %zu", len);
            handle_websocket_message(client, (char *)in, len);
            break;

        case LWS_CALLBACK_CLOSED:
            debug_log("WebSocket connection closed");
            cleanup_client(client);
            break;

        case LWS_CALLBACK_SERVER_WRITEABLE:
            debug_log("WebSocket writeable callback");
            break;

        default:
            debug_log("Unhandled WebSocket callback reason: %d", reason);
            break;
    }

    return 0;
}

// WebSocket protocols
static struct lws_protocols protocols[] = {
    {
        .name = "mumble",
        .callback = callback_mumble,
        .per_session_data_size = sizeof(struct client_session),
        .rx_buffer_size = 4096,
        .id = 0,
        .user = NULL,
    },
    {
        .name = NULL,
        .callback = NULL,
        .per_session_data_size = 0,
        .rx_buffer_size = 0,
        .id = 0,
        .user = NULL,
    }
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
    debug_log("Attempting to connect to Mumble server at %s:%d", host, MUMBLE_PORT);
    
    struct sockaddr_in addr;
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        debug_log("Socket creation failed: %s", strerror(errno));
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(MUMBLE_PORT);
    if (inet_pton(AF_INET, host, &addr.sin_addr) <= 0) {
        debug_log("Invalid address: %s", host);
        close(sock);
        return -1;
    }

    debug_log("Connecting to socket...");
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        debug_log("Connect failed: %s", strerror(errno));
        close(sock);
        return -1;
    }

    debug_log("Socket connected, setting up SSL...");
    client->mumble_fd = sock;
    client->ssl = SSL_new(server_state.ssl_ctx);
    if (!client->ssl) {
        debug_log("SSL_new failed");
        close(sock);
        return -1;
    }

    SSL_set_fd(client->ssl, sock);
    debug_log("Performing SSL handshake...");
    
    int ret = SSL_connect(client->ssl);
    if (ret <= 0) {
        debug_log("SSL handshake failed: %s", ERR_error_string(ERR_get_error(), NULL));
        SSL_free(client->ssl);
        close(sock);
        return -1;
    }

    debug_log("SSL connection established");
    return 0;
}

// Create Mumble version packet
static int send_version_packet(struct client_session *client) {
    unsigned char packet[12];
    uint16_t type = htons(Version);
    uint32_t version = htonl(MUMBLE_VERSION_2);
    
    memcpy(packet, &type, 2);
    memcpy(packet + 2, &version, 4);
    memset(packet + 6, 0, 6);  // Release, OS, OS Version
    
    int ret = SSL_write(client->ssl, packet, sizeof(packet));
    CHECK_SSL(ret, "Failed to send version packet");
    
    debug_log("Sent version packet");
    return 0;
}

// Create Mumble authentication packet
static int send_auth_packet(struct client_session *client) {
    json_t *auth = json_object();
    CHECK_NULL(auth, "Failed to create auth JSON object");
    
    json_object_set_new(auth, "username", json_string(client->username));
    json_object_set_new(auth, "password", json_string(""));  // No password for now
    
    char *auth_str = json_dumps(auth, JSON_COMPACT);
    CHECK_NULL(auth_str, "Failed to serialize auth JSON");
    
    size_t payload_len = strlen(auth_str);
    size_t packet_len = payload_len + 6;
    unsigned char *packet = malloc(packet_len);
    CHECK_NULL(packet, "Failed to allocate auth packet");
    
    uint16_t type = htons(Authenticate);
    uint32_t length = htonl(payload_len);
    
    memcpy(packet, &type, 2);
    memcpy(packet + 2, &length, 4);
    memcpy(packet + 6, auth_str, payload_len);
    
    int ret = SSL_write(client->ssl, packet, packet_len);
    
    free(packet);
    free(auth_str);
    json_decref(auth);
    
    CHECK_SSL(ret, "Failed to send auth packet");
    
    debug_log("Sent auth packet for user %s", client->username);
    return 0;
}

// Handle Mumble server packets
static void handle_mumble_packet(struct client_session *client, const unsigned char *data, size_t len) {
    if (len < 6) {
        debug_log("Received too short packet: %zu bytes", len);
        return;
    }
    
    uint16_t type;
    uint32_t length;
    memcpy(&type, data, 2);
    memcpy(&length, data + 2, 4);
    type = ntohs(type);
    length = ntohl(length);
    
    debug_log("Received Mumble packet: type=%d, length=%u", type, length);
    
    const unsigned char *payload = data + 6;
    
    switch (type) {
        case Version:
            debug_log("Received Version packet, sending auth");
            send_auth_packet(client);
            break;
            
        case UserState: {
            debug_log("Received UserState packet");
            // Create user state JSON
            json_t *user = json_object();
            json_t *users = json_array();
            
            // Parse Mumble protocol buffer (simplified for example)
            uint32_t session_id;
            char name[128];
            int muted = 0, deafened = 0;
            
            memcpy(&session_id, payload, 4);
            session_id = ntohl(session_id);
            
            // Extract name (assuming it follows session ID)
            size_t name_len = strnlen((char *)payload + 4, length - 4);
            strncpy(name, (char *)payload + 4, name_len);
            name[name_len] = '\0';
            
            // Create user object
            json_object_set_new(user, "session", json_integer(session_id));
            json_object_set_new(user, "name", json_string(name));
            json_object_set_new(user, "muted", json_boolean(muted));
            json_object_set_new(user, "deafened", json_boolean(deafened));
            
            json_array_append_new(users, user);
            
            // Create message
            json_t *msg = json_object();
            json_object_set_new(msg, "type", json_string("user-state"));
            json_object_set_new(msg, "users", users);
            
            char *msg_str = json_dumps(msg, JSON_COMPACT);
            forward_to_websocket(client, (unsigned char *)msg_str, strlen(msg_str));
            
            free(msg_str);
            json_decref(msg);
            break;
        }
        
        case ChannelState: {
            debug_log("Received ChannelState packet");
            // Create channel state JSON
            json_t *channel = json_object();
            json_t *channels = json_array();
            
            // Parse Mumble protocol buffer (simplified for example)
            uint32_t channel_id;
            char name[128];
            uint32_t user_count = 0;
            
            memcpy(&channel_id, payload, 4);
            channel_id = ntohl(channel_id);
            
            // Extract name (assuming it follows channel ID)
            size_t name_len = strnlen((char *)payload + 4, length - 4);
            strncpy(name, (char *)payload + 4, name_len);
            name[name_len] = '\0';
            
            // Create channel object
            json_object_set_new(channel, "id", json_integer(channel_id));
            json_object_set_new(channel, "name", json_string(name));
            json_object_set_new(channel, "users", json_integer(user_count));
            
            json_array_append_new(channels, channel);
            
            // Create message
            json_t *msg = json_object();
            json_object_set_new(msg, "type", json_string("channel-state"));
            json_object_set_new(msg, "channels", channels);
            
            char *msg_str = json_dumps(msg, JSON_COMPACT);
            forward_to_websocket(client, (unsigned char *)msg_str, strlen(msg_str));
            
            free(msg_str);
            json_decref(msg);
            break;
        }
        
        default:
            debug_log("Unhandled Mumble packet type: %d", type);
            break;
    }
}

// Modified handle_authentication function
static void handle_authentication(struct client_session *client) {
    debug_log("Attempting to connect to Mumble server: %s", client->server_host);
    
    if (connect_to_mumble(client, client->server_host) != 0) {
        debug_log("Failed to connect to Mumble server");
        lws_close_reason(client->wsi, LWS_CLOSE_STATUS_PROTOCOL_ERR, 
                        (unsigned char *)"Failed to connect to Mumble server", 31);
        return;
    }
    
    debug_log("Connected to Mumble server, sending version packet");
    if (send_version_packet(client) != 0) {
        debug_log("Failed to send version packet");
        cleanup_client(client);
        return;
    }
    
    client->authenticated = 1;
    debug_log("User %s connected to Mumble server %s", client->username, client->server_host);
    
    pthread_t recv_thread;
    if (pthread_create(&recv_thread, NULL, mumble_receive_thread, client) != 0) {
        debug_log("Failed to create receive thread");
        cleanup_client(client);
        return;
    }
    pthread_detach(recv_thread);
}

// Mumble receive thread
static void *mumble_receive_thread(void *arg) {
    struct client_session *client = (struct client_session *)arg;
    unsigned char buffer[4096];
    
    debug_log("Started Mumble receive thread for user %s", client->username);
    
    while (client->authenticated) {
        int bytes = SSL_read(client->ssl, buffer, sizeof(buffer));
        if (bytes <= 0) {
            if (bytes < 0) {
                debug_log("SSL_read error: %s", ERR_error_string(ERR_get_error(), NULL));
            } else {
                debug_log("SSL connection closed");
            }
            break;
        }
        
        debug_log("Received %d bytes from Mumble server", bytes);
        handle_mumble_packet(client, buffer, bytes);
    }
    
    debug_log("Mumble receive thread ending for user %s", client->username);
    
    if (client->authenticated) {
        client->authenticated = 0;
        lws_callback_on_writable(client->wsi);
    }
    
    pthread_exit(NULL);
}

// Handle incoming WebSocket messages
static void handle_websocket_message(struct client_session *client, char *msg, size_t len) {
    debug_log("Processing WebSocket message: %.*s", (int)len, msg);
    
    json_error_t error;
    json_t *root = json_loads(msg, 0, &error);
    if (!root) {
        debug_log("Failed to parse JSON: %s", error.text);
        return;
    }

    const char *type = json_string_value(json_object_get(root, "type"));
    if (!type) {
        debug_log("Message missing 'type' field");
        json_decref(root);
        return;
    }

    debug_log("Received message type: %s", type);

    if (strcmp(type, "user-info") == 0) {
        const char *username = json_string_value(json_object_get(root, "username"));
        if (username) {
            debug_log("User info received for: %s", username);
            strncpy(client->username, username, sizeof(client->username) - 1);
            client->username[sizeof(client->username) - 1] = '\0';
            
            // Start authentication process
            handle_authentication(client);
        } else {
            debug_log("User info missing username");
        }
    }
    else if (strcmp(type, "audio-data") == 0) {
        if (!client->authenticated) {
            debug_log("Received audio data but client not authenticated");
            json_decref(root);
            return;
        }
        
        json_t *data = json_object_get(root, "data");
        if (json_is_string(data)) {
            const char *audio_data = json_string_value(data);
            size_t decoded_len;
            unsigned char *decoded = base64_decode(audio_data, &decoded_len);
            if (decoded) {
                debug_log("Forwarding audio data, length: %zu", decoded_len);
                forward_to_mumble(client, decoded, decoded_len);
                free(decoded);
            } else {
                debug_log("Failed to decode audio data");
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
    if (client->server_host) {
        free(client->server_host);
        client->server_host = NULL;
    }
    client->authenticated = 0;
}

// Signal handler for graceful shutdown
static void signal_handler(int signum) {
    (void)signum;  // Mark signum as used to suppress warning
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
        debug_log("Failed to initialize SSL context");
        return 1;
    }

    // WebSocket server config
    struct lws_context_creation_info info;
    memset(&info, 0, sizeof(info));
    
    info.port = WS_PORT;
    info.protocols = protocols;
    info.gid = -1;
    info.uid = -1;
    info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
    
    // Set up logging
    int logs = LLL_ERR | LLL_WARN | LLL_NOTICE;
    lws_set_log_level(logs, NULL);

    debug_log("Creating WebSocket context on port %d", WS_PORT);
    
    // Create WebSocket context
    server_state.ws_context = lws_create_context(&info);
    if (!server_state.ws_context) {
        debug_log("Failed to create WebSocket context");
        SSL_CTX_free(server_state.ssl_ctx);
        return 1;
    }

    debug_log("Mumble WebSocket bridge server running on port %d...", WS_PORT);

    // Main event loop
    while (server_state.running) {
        int n = lws_service(server_state.ws_context, 50);
        if (n < 0) {
            debug_log("WebSocket service error: %d", n);
            break;
        }
    }

    debug_log("Server shutting down...");

    // Cleanup
    lws_context_destroy(server_state.ws_context);
    SSL_CTX_free(server_state.ssl_ctx);
    EVP_cleanup();

    return 0;
} 