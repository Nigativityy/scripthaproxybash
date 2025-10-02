const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const fs = require('fs');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = socketIo(server);

// --- Configuration ---
const PORT = 3000;
const PUBLIC_DIR = path.join(__dirname, 'public');
const RESULTS_FILE_PATH = '/home/cyber/results.json';

// Serve the HTML, CSS, and client-side JS files from the 'public' directory
app.use(express.static(PUBLIC_DIR));

// Route for the main page
app.get('/', (req, res) => {
    res.sendFile(path.join(PUBLIC_DIR, 'index.html'));
});

// Route for initially fetching the results via HTTP (useful for the first page load)
app.get('/results', (req, res) => {
    fs.readFile(RESULTS_FILE_PATH, 'utf8', (err, data) => {
        if (err) {
            console.error('Error reading results file:', err);
            return res.status(500).send('Error reading results file');
        }
        res.setHeader('Content-Type', 'application/json');
        res.send(data);
    });
});

// --- Socket.IO Connection Handling ---
io.on('connection', (socket) => {
    console.log(`New client connected: ${socket.id}`);

    // Immediately send the current results to the newly connected client
    fs.readFile(RESULTS_FILE_PATH, 'utf8', (err, data) => {
        if (err) {
            console.error('Error reading results file for new client:', err);
        } else {
            socket.emit('update', data);
        }
    });

    socket.on('disconnect', () => {
        console.log(`Client disconnected: ${socket.id}`);
    });
});

// --- File Watcher for Real-Time Updates ---
// This is the key improvement. It watches for any changes to results.json.
console.log(`Watching for file changes on: ${RESULTS_FILE_PATH}`);

fs.watch(RESULTS_FILE_PATH, (eventType, filename) => {
    // We only care about the 'change' event when the file is modified
    if (eventType === 'change') {
        console.log('File changed. Reading and broadcasting update...');

        fs.readFile(RESULTS_FILE_PATH, 'utf8', (err, data) => {
            if (err) {
                console.error('Error reading updated results file:', err);
                return;
            }
            // Broadcast the new data to ALL connected clients
            io.emit('update', data);
            console.log('Update successfully broadcasted to all clients.');
        });
    }
});


// Start the server
server.listen(PORT, () => {
    console.log(`Server listening on port ${PORT}`);
});
