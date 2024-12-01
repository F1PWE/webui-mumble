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
#include <netdb.h>
#include <time.h>
#include <sys/select.h>
#include <fcntl.h>

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
#define PING_INTERVAL 5  // Send ping every 5 seconds

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
static void handle_ssl_error(SSL *ssl, int ret);
static void send_status_message(struct client_session *client, const char *status, const char *reason);
static void handle_websocket_message(struct client_session *client, char *msg, size_t len);
static void handle_mumble_packet(struct client_session *client, const unsigned char *data, size_t len);
static void forward_to_websocket(struct client_session *client, const unsigned char *data, size_t len);
static void cleanup_client(struct client_session *client);
static int connect_to_mumble(struct client_session *client, const char *host);
static int send_version_packet(struct client_session *client);
static int send_auth_packet(struct client_session *client);
static int send_ping_packet(struct client_session *client);
static void *mumble_receive_thread(void *arg);

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
        case LWS_CALLBACK_PROTOCOL_INIT:
            debug_log("Protocol initialized");
            break;
            
        case LWS_CALLBACK_PROTOCOL_DESTROY:
            debug_log("Protocol destroyed");
            break;
            
        case LWS_CALLBACK_ESTABLISHED:
            debug_log("WebSocket connection established");
            if (!client) {
                debug_log("Failed to allocate client session");
                return -1;
            }
            client->wsi = wsi;
            client->mumble_fd = -1;
            client->authenticated = 0;
            client->server_host = NULL;
            debug_log("Client session initialized");
            break;
            
        case LWS_CALLBACK_CLOSED:
            debug_log("WebSocket connection closed, cleaning up client");
            cleanup_client(client);
            break;
            
        case LWS_CALLBACK_RECEIVE:
            if (len > 0 && in) {
                debug_log("WebSocket data received, length: %zu, data: %.*s", len, (int)len, (char *)in);
                char *msg = malloc(len + 1);
                if (!msg) {
                    debug_log("Failed to allocate message buffer");
                    return -1;
                }
                memcpy(msg, in, len);
                msg[len] = '\0';
                handle_websocket_message(client, msg, len);
                free(msg);
            }
            break;
            
        case LWS_CALLBACK_SERVER_WRITEABLE:
            debug_log("WebSocket writeable callback");
            break;
            
        case LWS_CALLBACK_WSI_CREATE:
            debug_log("WebSocket instance created");
            break;
            
        case LWS_CALLBACK_WSI_DESTROY:
            debug_log("WebSocket instance destroyed");
            break;
            
        case LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION:
            debug_log("Filtering protocol connection");
            break;
            
        case LWS_CALLBACK_ADD_POLL_FD:
        case LWS_CALLBACK_DEL_POLL_FD:
        case LWS_CALLBACK_CHANGE_MODE_POLL_FD:
            // Silently handle polling callbacks
            break;
            
        default:
            debug_log("Unhandled callback reason: %d", reason);
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
    
    struct addrinfo hints, *result, *rp;
    char port_str[6];
    int sock = -1;
    
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;    // Allow IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_ADDRCONFIG;
    
    snprintf(port_str, sizeof(port_str), "%d", MUMBLE_PORT);
    
    int ret = getaddrinfo(host, port_str, &hints, &result);
    if (ret != 0) {
        debug_log("Failed to resolve host %s: %s", host, gai_strerror(ret));
        return -1;
    }
    
    // Try each address until we successfully connect
    for (rp = result; rp != NULL; rp = rp->ai_next) {
        sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock == -1) {
            continue;
        }
        
        // Set socket options
        int flag = 1;
        setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
        
        // Set socket timeouts
        struct timeval tv;
        tv.tv_sec = 5;  // 5 seconds timeout
        tv.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof tv);
        
        // Set non-blocking mode
        int flags = fcntl(sock, F_GETFL, 0);
        fcntl(sock, F_SETFL, flags | O_NONBLOCK);
        
        if (connect(sock, rp->ai_addr, rp->ai_addrlen) != -1 || errno == EINPROGRESS) {
            // Connected or connection in progress
            char addr_str[INET6_ADDRSTRLEN];
            void *addr;
            if (rp->ai_family == AF_INET) {
                addr = &((struct sockaddr_in *)rp->ai_addr)->sin_addr;
            } else {
                addr = &((struct sockaddr_in6 *)rp->ai_addr)->sin6_addr;
            }
            inet_ntop(rp->ai_family, addr, addr_str, sizeof(addr_str));
            debug_log("Connected to address: %s", addr_str);
            break;
        }
        
        close(sock);
        sock = -1;
    }
    
    freeaddrinfo(result);
    
    if (sock == -1) {
        debug_log("Could not connect to any resolved addresses for %s", host);
        return -1;
    }
    
    debug_log("Socket connected, setting up SSL...");
    client->ssl = SSL_new(server_state.ssl_ctx);
    if (!client->ssl) {
        debug_log("SSL_new failed: %s", ERR_error_string(ERR_get_error(), NULL));
        close(sock);
        return -1;
    }
    
    SSL_set_fd(client->ssl, sock);
    SSL_set_mode(client->ssl, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    debug_log("Performing SSL handshake...");
    
    ret = SSL_connect(client->ssl);
    if (ret <= 0) {
        int err = SSL_get_error(client->ssl, ret);
        debug_log("SSL handshake failed: %s (error: %d)", ERR_error_string(ERR_get_error(), NULL), err);
        SSL_free(client->ssl);
        close(sock);
        return -1;
    }
    
    debug_log("SSL connection established, cipher: %s", SSL_get_cipher(client->ssl));
    client->mumble_fd = sock;
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

// Send ping packet
static int send_ping_packet(struct client_session *client) {
    unsigned char packet[6];
    uint16_t type = htons(Ping);
    uint32_t length = 0;
    
    memcpy(packet, &type, 2);
    memcpy(packet + 2, &length, 4);
    
    int ret = SSL_write(client->ssl, packet, sizeof(packet));
    if (ret <= 0) {
        handle_ssl_error(client->ssl, ret);
        return -1;
    }
    
    debug_log("Sent ping packet");
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
    
    switch (type) {
        case Version: {
            debug_log("Received Version packet, sending auth");
            send_auth_packet(client);
            
            // Send status update to client
            json_t *status = json_object();
            json_object_set_new(status, "type", json_string("connection-state"));
            json_object_set_new(status, "status", json_string("version-received"));
            char *status_str = json_dumps(status, JSON_COMPACT);
            if (status_str) {
                forward_to_websocket(client, (unsigned char *)status_str, strlen(status_str));
                free(status_str);
            }
            json_decref(status);
            break;
        }
        
        case Authenticate: {
            debug_log("Received Authentication response");
            // Forward the authentication response to client
            forward_to_websocket(client, data, len);
            break;
        }
        
        default:
            // Forward all other packets to client
            forward_to_websocket(client, data, len);
            break;
    }
}

// Forward Mumble server data to WebSocket client
static void forward_to_websocket(struct client_session *client, const unsigned char *data, size_t len) {
    if (!client || !client->wsi) return;
    
    // Create JSON message
    json_t *msg = json_object();
    json_object_set_new(msg, "type", json_string("mumble-data"));
    
    // If it's a text message, send it directly
    if (data[0] == '{') {
        json_object_set_new(msg, "messageType", json_integer(0));  // Control message
        json_object_set_new(msg, "data", json_string((const char *)data));
    } else {
        // For binary Mumble protocol messages
        uint16_t type;
        memcpy(&type, data, 2);
        type = ntohs(type);
        json_object_set_new(msg, "messageType", json_integer(type));
        
        // Convert binary data to base64
        size_t b64_len = ((len + 2) / 3) * 4 + 1;
        char *b64_data = malloc(b64_len);
        if (!b64_data) {
            json_decref(msg);
            return;
        }
        
        EVP_EncodeBlock((unsigned char*)b64_data, data, len);
        json_object_set_new(msg, "data", json_string(b64_data));
        free(b64_data);
    }
    
    // Convert to string
    char *json_str = json_dumps(msg, JSON_COMPACT);
    json_decref(msg);
    
    if (!json_str) return;
    
    // Send via WebSocket
    unsigned char *ws_buf = malloc(LWS_PRE + strlen(json_str));
    if (!ws_buf) {
        free(json_str);
        return;
    }
    
    memcpy(ws_buf + LWS_PRE, json_str, strlen(json_str));
    lws_write(client->wsi, ws_buf + LWS_PRE, strlen(json_str), LWS_WRITE_TEXT);
    
    free(ws_buf);
    free(json_str);
}

// Send status message to client
static void send_status_message(struct client_session *client, const char *status, const char *reason) {
    json_t *msg = json_object();
    json_object_set_new(msg, "type", json_string("connection-state"));
    json_object_set_new(msg, "status", json_string(status));
    if (reason) {
        json_object_set_new(msg, "reason", json_string(reason));
    }
    
    char *msg_str = json_dumps(msg, JSON_COMPACT);
    if (msg_str) {
        forward_to_websocket(client, (unsigned char *)msg_str, strlen(msg_str));
        free(msg_str);
    }
    json_decref(msg);
}

// Handle authentication
static void handle_authentication(struct client_session *client) {
    debug_log("Attempting to connect to Mumble server: %s", client->server_host);
    
    if (connect_to_mumble(client, client->server_host) != 0) {
        send_status_message(client, "error", "Failed to connect to Mumble server");
        return;
    }
    
    debug_log("Connected to Mumble server, sending version packet");
    if (send_version_packet(client) != 0) {
        debug_log("Failed to send version packet");
        send_status_message(client, "error", "Failed to send version packet");
        cleanup_client(client);
        return;
    }
    
    client->authenticated = 1;
    debug_log("User %s connected to Mumble server %s", client->username, client->server_host);
    
    // Send success message
    json_t *state = json_object();
    json_object_set_new(state, "type", json_string("connection-state"));
    json_object_set_new(state, "status", json_string("authenticated"));
    json_object_set_new(state, "username", json_string(client->username));
    
    char *state_str = json_dumps(state, JSON_COMPACT);
    if (state_str) {
        debug_log("Sending authentication success to client");
        forward_to_websocket(client, (unsigned char *)state_str, strlen(state_str));
        free(state_str);
    }
    json_decref(state);
    
    // Start receive thread
    pthread_t recv_thread;
    if (pthread_create(&recv_thread, NULL, mumble_receive_thread, client) != 0) {
        debug_log("Failed to create receive thread");
        send_status_message(client, "error", "Failed to start receive thread");
        cleanup_client(client);
        return;
    }
    pthread_detach(recv_thread);
}

// Function to handle SSL errors
static void handle_ssl_error(SSL *ssl, int ret) {
    int err = SSL_get_error(ssl, ret);
    unsigned long e;
    
    switch (err) {
        case SSL_ERROR_ZERO_RETURN:
            debug_log("SSL connection closed cleanly");
            break;
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
            debug_log("SSL operation would block");
            break;
        case SSL_ERROR_SYSCALL:
            e = ERR_get_error();
            if (e == 0) {
                if (ret == 0) {
                    debug_log("SSL EOF observed");
                } else {
                    debug_log("SSL syscall error: %s", strerror(errno));
                }
            } else {
                debug_log("SSL syscall error: %s", ERR_error_string(e, NULL));
            }
            break;
        default:
            debug_log("SSL error: %s", ERR_error_string(err, NULL));
            break;
    }
}

// Mumble receive thread
static void *mumble_receive_thread(void *arg) {
    struct client_session *client = (struct client_session *)arg;
    unsigned char buffer[4096];
    int bytes;
    time_t last_ping = time(NULL);
    
    debug_log("Started Mumble receive thread for user %s", client->username);
    
    while (client->authenticated) {
        // Set up select for SSL read
        fd_set read_fds;
        struct timeval tv;
        FD_ZERO(&read_fds);
        FD_SET(client->mumble_fd, &read_fds);
        
        // Wait up to 1 second for data
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        
        int ready = select(client->mumble_fd + 1, &read_fds, NULL, NULL, &tv);
        if (ready < 0) {
            if (errno == EINTR) continue;
            debug_log("Select error: %s", strerror(errno));
            break;
        }
        
        // Check if it's time to send a ping
        time_t now = time(NULL);
        if (now - last_ping >= PING_INTERVAL) {
            if (send_ping_packet(client) == 0) {
                last_ping = now;
            } else {
                debug_log("Failed to send ping packet");
                break;
            }
        }
        
        // If no data is available, continue the loop
        if (ready == 0) continue;
        
        // Try to read data
        bytes = SSL_read(client->ssl, buffer, sizeof(buffer));
        if (bytes <= 0) {
            int ssl_error = SSL_get_error(client->ssl, bytes);
            if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
                // Non-blocking operation would block, try again
                continue;
            }
            
            handle_ssl_error(client->ssl, bytes);
            if (bytes == 0) {
                debug_log("Connection closed by peer");
            } else {
                debug_log("SSL_read error occurred");
            }
            
            // Notify client about disconnection
            send_status_message(client, "disconnected", "Server connection lost");
            break;
        }
        
        debug_log("Received %d bytes from Mumble server", bytes);
        handle_mumble_packet(client, buffer, bytes);
    }
    
    debug_log("Mumble receive thread ending for user %s", client->username);
    
    // Clean up connection
    cleanup_client(client);
    return NULL;
}

// Handle incoming WebSocket messages
static void handle_websocket_message(struct client_session *client, char *msg, size_t len) {
    (void)len;  // Suppress unused parameter warning
    
    json_error_t error;
    json_t *root = json_loads(msg, 0, &error);
    
    if (!root) {
        debug_log("Failed to parse JSON message: %s", error.text);
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
            
            // Store server host
            const char *server = json_string_value(json_object_get(root, "server"));
            if (server) {
                debug_log("Using specified server: %s", server);
                client->server_host = strdup(server);
            } else {
                debug_log("Using default server: %s", DEFAULT_HOST);
                client->server_host = strdup(DEFAULT_HOST);
            }
            
            if (!client->server_host) {
                debug_log("Failed to allocate server host");
                json_decref(root);
                return;
            }
            
            // Start authentication process
            debug_log("Starting authentication for user: %s on server: %s", username, client->server_host);
            handle_authentication(client);
        } else {
            debug_log("User info missing username");
        }
    } else {
        debug_log("Unknown message type: %s", type);
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

// Clean up client resources
static void cleanup_client(struct client_session *client) {
    if (!client) return;
    
    debug_log("Cleaning up client resources");
    
    // Mark as not authenticated first to stop receive thread
    client->authenticated = 0;
    
    if (client->ssl) {
        debug_log("Shutting down SSL connection");
        SSL_shutdown(client->ssl);
        SSL_free(client->ssl);
        client->ssl = NULL;
    }
    
    if (client->mumble_fd >= 0) {
        debug_log("Closing socket");
        close(client->mumble_fd);
        client->mumble_fd = -1;
    }
    
    if (client->server_host) {
        debug_log("Freeing server host");
        free(client->server_host);
        client->server_host = NULL;
    }
    
    // Notify client about cleanup
    json_t *status = json_object();
    json_object_set_new(status, "type", json_string("connection-state"));
    json_object_set_new(status, "status", json_string("cleanup-complete"));
    
    char *status_str = json_dumps(status, JSON_COMPACT);
    if (status_str && client->wsi) {
        forward_to_websocket(client, (unsigned char *)status_str, strlen(status_str));
        free(status_str);
    }
    json_decref(status);
    
    debug_log("Client cleanup complete");
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
    
    // Initialize OpenSSL
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    
    // Create SSL context
    server_state.ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!server_state.ssl_ctx) {
        debug_log("Failed to create SSL context");
        return 1;
    }
    
    // WebSocket protocol structure
    struct lws_protocols protocols[] = {
        {
            "mumble-protocol",
            callback_mumble,
            sizeof(struct client_session),
            4096,  // rx buffer size
            0,     // id
            NULL,  // user pointer
            4096   // tx packet size
        },
        { NULL, NULL, 0, 0, 0, NULL, 0 }  // terminator
    };
    
    // WebSocket context creation info
    struct lws_context_creation_info info = {
        .port = WS_PORT,
        .protocols = protocols,
        .gid = -1,
        .uid = -1,
        .options = LWS_SERVER_OPTION_VALIDATE_UTF8 |
                  LWS_SERVER_OPTION_HTTP_HEADERS_SECURITY_BEST_PRACTICES_ENFORCE |
                  LWS_SERVER_OPTION_PEER_CERT_NOT_REQUIRED,
        .max_http_header_pool = 16,
        .max_http_header_data = 2048,
        .ws_ping_pong_interval = 30,
        .keepalive_timeout = 60,
        .timeout_secs = 60,
        .simultaneous_ssl_restriction = 100,
        .ssl_options_set = SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1
    };
    
    debug_log("Creating WebSocket context...");
    server_state.ws_context = lws_create_context(&info);
    if (!server_state.ws_context) {
        debug_log("Failed to create WebSocket context");
        return 1;
    }
    
    debug_log("Server started on port %d", WS_PORT);
    
    // Main event loop
    while (server_state.running) {
        lws_service(server_state.ws_context, 50);
    }
    
    // Cleanup
    debug_log("Server shutting down...");
    lws_context_destroy(server_state.ws_context);
    SSL_CTX_free(server_state.ssl_ctx);
    EVP_cleanup();
    
    return 0;
} 