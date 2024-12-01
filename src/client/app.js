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
            this.audioStream = await navigator.mediaDevices.getUserMedia({
                audio: {
                    echoCancellation: true,
                    noiseSuppression: true,
                    autoGainControl: true
                },
                video: false
            });

            this.updateStatus('Connecting to server...');

            // Create WebSocket connection with retry logic
            const connectWebSocket = () => {
                this.connection = new WebSocket(`wss://nimmerchat.xyz/mumble`);
                
                this.connection.onopen = () => {
                    console.log('WebSocket connected');
                    this.updateStatus('Connected to WebSocket, authenticating...');
                    // Send initial user data
                    this.connection.send(JSON.stringify({
                        type: 'user-info',
                        username: this.usernameInput.value || 'Guest'
                    }));
                    this.isConnected = true;
                    this.updateButtons();
                };

                this.connection.onclose = (event) => {
                    console.log('WebSocket closed:', event);
                    this.updateStatus('Disconnected');
                    this.isConnected = false;
                    this.updateButtons();
                    
                    // Try to reconnect after 5 seconds
                    if (!event.wasClean) {
                        this.updateStatus('Connection lost, retrying in 5s...');
                        setTimeout(connectWebSocket, 5000);
                    }
                };

                this.connection.onerror = (error) => {
                    console.error('WebSocket error:', error);
                    this.updateStatus('Connection error');
                    this.isConnected = false;
                    this.updateButtons();
                };

                this.connection.onmessage = (msg) => {
                    console.log('Received message:', msg.data);
                    this.handleMessage(msg);
                };
            };

            // Start the connection
            connectWebSocket();

            // Initialize WebRTC
            this.initializeWebRTC();
        } catch (error) {
            console.error('Connection failed:', error);
            this.updateStatus('Connection failed: ' + error.message);
            this.isConnected = false;
            this.updateButtons();
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
            username: this.usernameInput.value || 'Guest'
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

    handleMessage(msg) {
        try {
            console.log('Processing message:', msg.data);
            const data = JSON.parse(msg.data);
            switch (data.type) {
                case 'user-state':
                    console.log('Updating user list:', data.users);
                    this.updateUserList(data.users);
                    break;
                case 'channel-state':
                    console.log('Updating channel list:', data.channels);
                    this.updateChannelList(data.channels);
                    break;
                case 'error':
                    console.error('Server error:', data.message);
                    this.updateStatus('Error: ' + data.message);
                    break;
                default:
                    console.log('Unknown message type:', data.type);
            }
        } catch (error) {
            console.error('Error handling message:', error);
        }
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