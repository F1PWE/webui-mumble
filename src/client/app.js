// WebRTC configuration
const rtcConfig = {
    iceServers: [
        { urls: 'stun:stun.l.google.com:19302' }
    ]
};

class MumbleClient {
    constructor() {
        this.connection = null;
        this.peerConnection = null;
        this.audioStream = null;
        this.isConnected = false;
        this.isMuted = false;
        this.isDeafened = false;

        // DOM elements
        this.connectBtn = document.getElementById('connect');
        this.disconnectBtn = document.getElementById('disconnect');
        this.muteBtn = document.getElementById('mute');
        this.deafenBtn = document.getElementById('deafen');
        this.volumeSlider = document.getElementById('volume');
        this.usernameInput = document.getElementById('username');
        this.statusElement = document.getElementById('connection-status');

        this.bindEvents();
    }

    bindEvents() {
        this.connectBtn.onclick = () => this.connect();
        this.disconnectBtn.onclick = () => this.disconnect();
        this.muteBtn.onclick = () => this.toggleMute();
        this.deafenBtn.onclick = () => this.toggleDeafen();
        this.volumeSlider.oninput = (e) => this.setVolume(e.target.value);
    }

    async connect() {
        try {
            this.updateStatus('Requesting microphone access...');
            
            // Get microphone access
            navigator.mediaDevices.getUserMedia({
                audio: {
                    echoCancellation: true,
                    noiseSuppression: true,
                    autoGainControl: true
                },
                video: false
            }).then(stream => {
                this.audioStream = stream;
                this.updateStatus('Connecting to server...');

                // Create WebSocket connection using current hostname
                const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
                const wsUrl = `${wsProtocol}//${window.location.host}/mumble`;
                this.connection = new WebSocket(wsUrl);
                
                this.connection.binaryType = 'arraybuffer';
                
                this.connection.onopen = () => {
                    console.log('WebSocket connected');
                    this.updateStatus('Connected to WebSocket, authenticating...');
                    // Send initial user data
                    this.connection.send(JSON.stringify({
                        type: 'user-info',
                        username: this.usernameInput.value || 'Guest',
                        server: 'nimmerchat.xyz'
                    }));
                };

                this.connection.onclose = (event) => {
                    console.log('WebSocket closed:', event);
                    this.updateStatus('Disconnected');
                    this.isConnected = false;
                    this.updateButtons();
                    
                    if (!event.wasClean) {
                        this.updateStatus('Connection lost, retrying in 5s...');
                        setTimeout(() => this.connect(), 5000);
                    }
                };

                this.connection.onerror = (error) => {
                    console.error('WebSocket error:', error);
                    this.updateStatus('Connection error');
                    this.isConnected = false;
                    this.updateButtons();
                };

                this.connection.onmessage = async (msg) => {
                    try {
                        let data;
                        if (msg.data instanceof ArrayBuffer) {
                            // Handle binary data (Mumble protocol packets)
                            this.handleBinaryMessage(new Uint8Array(msg.data));
                            return;
                        } else if (msg.data instanceof Blob) {
                            // Convert Blob to text
                            data = await msg.data.text();
                        } else {
                            // Already text
                            data = msg.data;
                        }
                        
                        // Parse and handle JSON messages
                        console.log('Processing message:', data);
                        const jsonData = JSON.parse(data);
                        this.handleMessage(jsonData);
                    } catch (error) {
                        console.error('Error handling message:', error);
                        this.updateStatus('Error processing server message');
                    }
                };

            }).catch(error => {
                console.error('Microphone access failed:', error);
                this.updateStatus('Microphone access denied');
            });

        } catch (error) {
            console.error('Connection failed:', error);
            this.updateStatus('Connection failed: ' + error.message);
        }
    }

    handleBinaryMessage(data) {
        // First 2 bytes are message type
        const type = (data[0] << 8) | data[1];
        // Next 4 bytes are length
        const length = (data[2] << 24) | (data[3] << 16) | (data[4] << 8) | data[5];
        // Remaining bytes are payload
        const payload = data.slice(6, 6 + length);

        console.log('Binary message:', { type, length, payload });

        switch (type) {
            case 0: // Version
                console.log('Received Version message');
                break;
            case 2: // Authentication
                console.log('Received Authentication message');
                this.updateStatus('Authentication response received');
                break;
            case 9: // UserState
                console.log('Received UserState message');
                break;
            default:
                console.log('Received unknown message type:', type);
        }
    }

    handleMessage(data) {
        switch (data.type) {
            case 'connection-state':
                console.log('Connection state update:', data.status);
                if (data.status === 'authenticated') {
                    this.updateStatus('Connected as ' + data.username);
                    this.isConnected = true;
                    this.updateButtons();
                } else if (data.status === 'version-received') {
                    this.updateStatus('Server version received, authenticating...');
                }
                break;
            
            case 'mumble-data':
                console.log('Received Mumble data, type:', data.messageType);
                // Handle binary data in base64 format
                const binaryData = atob(data.data);
                this.handleMumbleData(data.messageType, binaryData);
                break;
            
            case 'error':
                console.error('Server error:', data.message);
                this.updateStatus('Error: ' + data.message);
                break;
            
            default:
                console.log('Unknown message type:', data.type);
        }
    }

    handleMumbleData(type, data) {
        switch (type) {
            case 0: // Version
                console.log('Received Version message');
                this.updateStatus('Version received');
                break;
            
            case 2: // Authentication
                console.log('Received Authentication message');
                this.updateStatus('Authentication response received');
                break;
            
            case 7: // ChannelState
                console.log('Received Channel State');
                // Handle channel state update
                break;
            
            case 9: // UserState
                console.log('Received User State');
                // Handle user state update
                break;
            
            default:
                console.log('Received unknown Mumble message type:', type);
        }
    }

    initializeWebRTC() {
        this.peerConnection = new RTCPeerConnection(rtcConfig);
        
        // Add audio track to peer connection
        this.audioStream.getAudioTracks().forEach(track => {
            this.peerConnection.addTrack(track, this.audioStream);
        });

        // Handle ICE candidates
        this.peerConnection.onicecandidate = (event) => {
            if (event.candidate) {
                this.connection.send(JSON.stringify({
                    type: 'ice-candidate',
                    candidate: event.candidate
                }));
            }
        };

        // Handle incoming audio streams
        this.peerConnection.ontrack = (event) => {
            const audio = new Audio();
            audio.srcObject = event.streams[0];
            audio.play();
        };
    }

    disconnect() {
        if (this.audioStream) {
            this.audioStream.getTracks().forEach(track => track.stop());
        }
        if (this.peerConnection) {
            this.peerConnection.close();
        }
        if (this.connection) {
            this.connection.close();
        }

        this.isConnected = false;
        this.updateStatus('Disconnected');
        this.updateButtons();
    }

    toggleMute() {
        if (this.audioStream) {
            this.isMuted = !this.isMuted;
            this.audioStream.getAudioTracks().forEach(track => {
                track.enabled = !this.isMuted;
            });
            this.muteBtn.textContent = this.isMuted ? 'Unmute' : 'Mute';
        }
    }

    toggleDeafen() {
        this.isDeafened = !this.isDeafened;
        if (this.peerConnection) {
            this.peerConnection.getReceivers().forEach(receiver => {
                if (receiver.track) {
                    receiver.track.enabled = !this.isDeafened;
                }
            });
        }
        this.deafenBtn.textContent = this.isDeafened ? 'Undeafen' : 'Deafen';
        
        // If deafened, ensure we're also muted
        if (this.isDeafened && !this.isMuted) {
            this.toggleMute();
        }
    }

    setVolume(value) {
        if (this.peerConnection) {
            this.peerConnection.getReceivers().forEach(receiver => {
                if (receiver.track) {
                    receiver.track.volume = value / 100;
                }
            });
        }
    }

    updateStatus(status) {
        console.log('Status update:', status);
        this.statusElement.textContent = status;
        this.statusElement.className = this.isConnected ? 'connected' : '';
    }

    updateButtons() {
        this.connectBtn.disabled = this.isConnected;
        this.disconnectBtn.disabled = !this.isConnected;
        this.muteBtn.disabled = !this.isConnected;
        this.deafenBtn.disabled = !this.isConnected;
        this.volumeSlider.disabled = !this.isConnected;
    }

    handleConnectionOpen() {
        // Send initial user data
        this.connection.send(JSON.stringify({
            type: 'user-info',
            username: this.usernameInput.value || 'Guest',
            server: 'nimmerchat.xyz'
        }));
    }

    handleConnectionClose() {
        this.disconnect();
    }

    handleConnectionError(error) {
        console.error('WebSocket error:', error);
        this.updateStatus('Connection error');
        this.disconnect();
    }

    updateUserList(users) {
        const usersList = document.getElementById('users-list');
        usersList.innerHTML = users.map(user => `
            <div class="user ${user.muted ? 'muted' : ''} ${user.deafened ? 'deafened' : ''}">
                <span class="username">${user.name}</span>
                ${user.muted ? '<span class="icon">🔇</span>' : ''}
                ${user.deafened ? '<span class="icon">🔈</span>' : ''}
            </div>
        `).join('');
    }

    updateChannelList(channels) {
        const channelList = document.getElementById('channel-list');
        channelList.innerHTML = channels.map(channel => `
            <div class="channel">
                <span class="channel-name">${channel.name}</span>
                <span class="user-count">${channel.users} users</span>
            </div>
        `).join('');
    }
}

// Initialize the client when the page loads
window.addEventListener('load', () => {
    window.mumbleClient = new MumbleClient();
}); 