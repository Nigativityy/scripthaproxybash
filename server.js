const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const fs = require('fs');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = socketIo(server);

app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/results', (req, res) => {
    fs.readFile('/home/cyber/results.json', 'utf8', (err, data) => {
        if (err) {
            return res.status(500).send('Error reading results file');
        }
        res.send(data);
    });
});

io.on('connection', (socket) => {
    console.log('New client connected');

    // Emit the results when a new client connects
    fs.readFile('/home/cyber/results.json', 'utf8', (err, data) => {
        if (!err) {
            socket.emit('update', data);
        }
    });

    socket.on('disconnect', () => {
        console.log('Client disconnected');
    });
});

server.listen(3000, () => {
    console.log('Listening on port 3000');
});
