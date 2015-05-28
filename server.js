var node_http = require('http');
var io = require('socket.io');
var pcap = require('pcap');
var fs = require('fs');
var util = require('util');

var Packet = require('./packet');
var Filter = require('./filter');


module.exports = Server;

/*
 * The default directory where all the pcap data is stored.
 */
var PCAP_DIR = __dirname + '/../pcapDir/'

/*
 * A test pcap data located in PCAP_DIR.
 */
var PCAP_FILE = PCAP_DIR + 'mypcap1mb.pcap';


/*
 * The function which serves as the constructor for the module.
 * @method Server
 * @param logger {object} The instance of the logging module.
 */
function Server(logger) {
    if (!logger) {
        // throw error
    }

    this.logs = logger.getLogger('server');

};

/**
 * Start up the node server.
 * @method start
 * @param app {object} The express application that will be included
 *                     in the server.
 *
 */
Server.prototype.start = function (app) {
    var self = this;
    self.app = app;

    // Start the http server with the express application as parameter.
    var server = node_http.createServer(app);

    // Instantiate a SocketIO namespace.
    var socketIO = io.listen(server);

    // Set the server to listen to port 8001. Once successful, callback is
    // invoked.
    server.listen(8001, function () {
        self.logs.info('Listening at: http://localhost:8001');
    });

    // Listen to a 'connection' event emitted by [socketIO].
    socketIO.on('connection', function (socket) {
        self.logs.info('Client ' + socket.id + ' has connected.');

        var rawPacketList = [];
        var decodedPacketList = [];
        var errorList = [];
        var origPacketList = [];
        var packetList = [];
        var sum = 24;

        socket.on('getFiles', function () {
            var files = getFileList();
            var jsonFileList = {0: '-----------'};
            for (var i = 1; i <= files.length; i++) {
                jsonFileList[i] = files[i-1];
            }
            socketIO.sockets.emit('files', jsonFileList);
        });

        socket.on('start', function (filename) {
            var counter = 0;
            var pcap_session, tcp_tracker;
            var dateNow = Date.now();
            var stats;
            // Instantiate a pcap_session.
            // An offline session detects packet data from a file.
            self.logs.info('Reading file: ' + PCAP_DIR + filename);

            try {
                handleFile(PCAP_DIR + filename);
            
                pcap_session = pcap.createOfflineSession(PCAP_DIR + filename, 'ip');
                stats = fs.statSync(PCAP_FILE);
            
                rawPacketList = [];
                decodedPacketList = [];
                errorList = [];
                origPacketList = [];
                packetList = [];

                tcp_tracker = new pcap.TCPTracker();

            

                //socketIO.sockets.emit('filesize', stats['size']);

                // Listen to a 'packet' event emmitted by [pcap_session].
                // Here we can do things to the packet data through the callback function.
                pcap_session.on('packet', function (packet) {
                    // Decode the packets based on its done by [pcap] automatically.
                    var fpacket = pcap.decode(packet);
                    sum += 16 + parseInt(fpacket.pcap_header.len);
                    var packetData = gatherTableDisplayData(counter++, fpacket);
                
                    packetList.push([packetData.counter, packetData.timestamp, packetData.srcIP, packetData.dstIP]);

                    // Emit an event 'packet' to the client.
                    socketIO.sockets.emit('packet', sum);

                    rawPacketList.push(packet);
                    decodedPacketList.push(fpacket);
                
                    // Track a tcp packet for its message.
                    // TODO: To be implemented yet.
                    tcp_tracker.track_packet(fpacket);
                });

                // Listen to a 'complete' event emitted by [pcap_session].
                // 'complete' is emitted once all packets in a session is read.
                pcap_session.on('complete', function () {
                    origPacketList = packetList;

                    // Emit a 'complete' event to the client.
                    self.logs.info('Packet load completed in: ' + (Date.now() - dateNow) + ' ms');
                    socketIO.sockets.emit('complete', packetList);
                    self.logs.info('Total: ' + sum + 'bytes');

                    fs.writeFile(PCAP_DIR + '赤さたな文字カナ.txt', '赤さたな文字カナ testing', {encoding: 'utf8'}, function (err) {
                        if (err) {
                            console.log(err);
                        } else {
                            console.log('Success');
                        }
                    });
                });

            } catch (err) {
                console.log(err.message);
                console.log('Blarghhhhhhh');
            }
        });

        // Listen to a 'disconnect' event emitted by [socket].
        socket.on('disconnect', function (reason) {
            self.logs.info('Client ' + socket.id + ' has disconnected.');
        });

        socket.on('selected', function(index) {
            self.logs.info('Selected index: ' + index);
            self.logs.info('Decoded Packet: ' + util.inspect(decodedPacketList[index]));
        });

        function handleFile(filename) {
            var valid = true;
            var file;
            fs.exists(filename, function (exists) {
                if (exists) {
                    file = fs.readFile(filename, function (err, data) {
                        if (err) {
                            valid = false;
                            handleError('ERR002', null);
                        }
                    });
                } else {
                    valid = false;
                    handleError('ERR001', null);
                }
            });
        };

        function handleError(errCode, message) {
            var err = {};
            err[errCode] = message;
            errorList.push(err);
            socketIO.sockets.emit('errorList', errorList);
        }

        function gatherTableDisplayData(counter, decoded_packet) {
            var packetData = new Packet();

            var networkLayer = decoded_packet.payload.payload;
            packetData.counter = counter;
            packetData.timestamp = packetData.dateFormat(decoded_packet.pcap_header.tv_sec, decoded_packet.pcap_header.tv_usec);
            if (networkLayer) {
                if (networkLayer.saddr && networkLayer.saddr.o1) {
                    packetData.srcIP = networkLayer.saddr.toString('ascii');
                    packetData.dstIP = networkLayer.daddr.toString('ascii');
                }
            }

            return packetData;
        }

        socket.on('validate', function (control, filter) {
            self.logs.info('Validating input:  ' + filter + 'for ' + control);
            
            var valid = true;
            if ('txtFilter' === control)  {
                var filterValidator = new Filter();
                valid = filterValidator.compileFilter(filter);
            } else if ('cmbFileList' === control) {
                valid = getFileList().indexOf(filter) != -1;
            }

            socketIO.sockets.emit('validated', valid);
        });

        socket.on('filter', function (filter) {
            self.logs.info(filter);

            var filterValidator = new Filter();
            var valid = filterValidator.compileFilter(filter);
            
            if (valid) {
                var filteredList = filterValidator.applyFilter(decodedPacketList);
                packetList = [];
                for (var i = 0; i < filteredList.length; i++) {
                    var packetData = gatherTableDisplayData(i, filteredList[i]);
                    packetList.push([packetData.counter, packetData.timestamp, packetData.srcIP, packetData.dstIP]);
                }

                if (0 == filter.length) {
                    packetList = origPacketList;
                }

                socketIO.sockets.emit('filtered', packetList);
            }
            
        })

        socket.on('error', function (err) {
            self.logs.info(err);
            if (0 <= errorList.length) {
                socketIO.sockets.emit('errorList', errorList);
            }
        });
    });

    /*
     * Gets a list of pcap files from the default directory.
     * @method getFileList
     * @returns filtered {array} An array of filenames in the said directory.
     */
    function getFileList() {
        try {
            self.logs.info('Reading ' + PCAP_DIR);

            var files = fs.readdirSync(PCAP_DIR);
            var filtered = files.filter(function (file) {
                return /\.pcap/i.test(file);
            });
            return filtered;
        } catch (err) {
            return;
        }
    }
};