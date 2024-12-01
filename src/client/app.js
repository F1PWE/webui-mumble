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
            // Get microphone access
            this.audioStream = await navigator.mediaDevices.getUserMedia({
                audio: {
                    echoCancellation: true,
                    noiseSuppression: true,
                    autoGainControl: true
                },
                video: false
            });

            // Create WebSocket connection to our server
            this.connection = new WebSocket(`wss://nimmerchat.xyz/mumble`);
            this.connection.onopen = () => this.handleConnectionOpen();
            this.connection.onclose = () => this.handleConnectionClose();
            this.connection.onerror = (error) => this.handleConnectionError(error);
            this.connection.onmessage = (msg) => this.handleMessage(msg);

            // Initialize WebRTC
            this.initializeWebRTC();

            this.updateStatus('Connected');
            this.isConnected = true;
            this.updateButtons();
        } catch (error) {
            console.error('Connection failed:', error);
            this.updateStatus('Connection failed');
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
        this.statusElement.textContent = status;
        this.statusElement.className = status === 'Connected' ? 'connected' : '';
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
            const data = JSON.parse(msg.data);
            switch (data.type) {
                case 'user-state':
                    this.updateUserList(data.users);
                    break;
                case 'channel-state':
                    this.updateChannelList(data.channels);
                    break;
                case 'error':
                    console.error('Server error:', data.message);
                    this.updateStatus('Error: ' + data.message);
                    break;
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