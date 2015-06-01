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
var PCAP_DIR = __dirname + '/../pcapDir/';


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
    var config;
    var self = this;
    self.app = app;

    try {
        config = JSON.parse(fs.readFileSync(__dirname + '/config/config.json', 'utf8'));
    } catch (e) {
        self.logs.error('GWSV028 failed to read config file[' + path + ']. reason: ' + e.message);
        return;
    }

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
        var filteredPacketList = [];

        var errorList = [];
        
        var origPacketList = [];
        var packetList = [];
        //var sum = 24;

        socket.on('getFiles', function () {
            var files = getFileList();
            var jsonFileList = {};
            for (var i = 1; i <= files.length; i++) {
                jsonFileList[i] = files[i-1];
            }

            if (files.length > 0) {
                socketIO.sockets.emit('files', jsonFileList);
            } else {
                handleError('ERR000', 'No .pcap files found.');
            }
        });

        /*
         * Gets a list of pcap files from the default directory.
         * @method getFileList
         * @returns filtered {array} An array of filenames in the said directory.
         */
        function getFileList() {
            self.logs.info('Reading ' + PCAP_DIR);

            var files = fs.readdirSync(PCAP_DIR);
            var filtered = files.filter(function (file) {
                return /\.pcap$/i.test(file);
            });
            return filtered;
        }

        socket.on('start', function (filename) {
            var counter = 0;
            var pcap_session, tcp_tracker;
            var dateNow = Date.now();
            // Instantiate a pcap_session.
            // An offline session detects packet data from a file.
            self.logs.info('Reading file: ' + PCAP_DIR + filename);
            try {
                handleFile(PCAP_DIR + filename);
            
                pcap_session = pcap.createOfflineSession(PCAP_DIR + filename, 'ip');
            
                rawPacketList = [];
                decodedPacketList = [];
                errorList = [];
                origPacketList = [];
                packetList = [];

                tcp_tracker = new pcap.TCPTracker();
                // Listen to a 'packet' event emmitted by [pcap_session].
                // Here we can do things to the packet data through the callback function.
                pcap_session.on('packet', function (packet) {
                    // Decode the packets based on its done by [pcap] automatically.
                    var fpacket = pcap.decode(packet);
                    //sum += 16 + parseInt(fpacket.pcap_header.len);
                    var packetData = gatherTableDisplayData(counter++, fpacket);
                
                    packetList.push([packetData.counter, packetData.timestamp, packetData.srcIP, packetData.dstIP]);

                    // Emit an event 'packet' to the client.
                    socketIO.sockets.emit('packet', 0);

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
                    filteredPacketList = decodedPacketList;
                    // Emit a 'complete' event to the client.
                    self.logs.info('Packet load completed in: ' + (Date.now() - dateNow) + ' ms');
                    socketIO.sockets.emit('complete', packetList);
                    //self.logs.info('Total: ' + sum + 'bytes');
                });

            } catch (err) {
                handleError('ERR001', err.message);
            }
        });

        // Listen to a 'disconnect' event emitted by [socket].
        socket.on('disconnect', function (reason) {
            self.logs.info('Client ' + socket.id + ' has disconnected.');
        });

        socket.on('selected', function (tabIndex, packetIndex) {
            if (0 == tabIndex) {
                hexadecimalFormat(packetIndex);
            } else {
                readableFormat(packetIndex);
            }
        });

        function hexadecimalFormat(packetIndex) {
            var currPacket = rawPacketList[packetIndex].buf;
            
        }

        function readableFormat(packetIndex) {
            var currPacket = filteredPacketList[packetIndex];
            var dataLinkLayer = currPacket.payload;
            var networkLayer = currPacket.payload.payload;
            var transportLayer = currPacket.payload.payload.payload;

            var formattedString = '';

            if (dataLinkLayer) {
                if (dataLinkLayer.dhost && dataLinkLayer.shost) {
                    formattedString += 'src:\t[' + dataLinkLayer.shost.toString('ascii') + '], ';
                    formattedString += 'dst:\t[' + dataLinkLayer.dhost.toString('ascii') + ']<br>';
                }
            }
            if (networkLayer) {
                if (networkLayer.saddr && networkLayer.saddr.o1) {
                    formattedString += 'IPv4, src: [' + networkLayer.saddr.toString('ascii') + '], ';
                    formattedString += 'dst: [' + networkLayer.daddr.toString('ascii') + ']<br>';
                }
            }
            if (transportLayer) {
                if (transportLayer.sport && transportLayer.dport) {
                    formattedString += 'Protocol: ['+ 'unknown' + '], ';
                    formattedString += 'src port: [' + transportLayer.sport + '], ';
                    formattedString += 'dst port: [' + transportLayer.dport + ']';
                }
            }
            socketIO.sockets.emit('decoded', formattedString);
        }

        function handleFile(filename) {
            var valid = true;
            var file;
            fs.exists(filename, function (exists) {
                if (!exists) {
                    valid = false;
                    handleError('ERR002', null);
                }
            });

            return valid;
        };

        function handleError(errCode, message) {
            var err = {};
            err['errCode'] = errCode;
            err['message'] = message;
            errorList = [];
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

        socket.on('filter', function (filter) {
            self.logs.info(filter);

            var filterValidator = new Filter();
            var valid = {};
            valid['result'] = filterValidator.compileFilter(filter);
            console.log(util.inspect(valid));
            self.logs.info(filter + ' is valid? ' + valid['result']);
            if (valid['result']) {
                var filteredList = filterValidator.applyFilter(decodedPacketList);
                filteredPacketList = filteredList;
                packetList = [];
                for (var i = 0; i < filteredList.length; i++) {
                    var packetData = gatherTableDisplayData(i, filteredList[i]);
                    packetList.push([packetData.counter, packetData.timestamp, packetData.srcIP, packetData.dstIP]);
                }

                if (0 == filter.length) {
                    packetList = origPacketList;
                    filteredPacketList = decodedPacketList;
                }
                socketIO.sockets.emit('filtered', packetList);
            } else {
                //handleError(valid['errCode'], valid['errorMessage']);
            }
        });

        socket.on('save', function (filename, filter) {
            self.logs.info('Saving file: ' + filename + '.txt');
            var txtFilename = filename.replace('.pcap', '');
            var time = new Date();

            var timestamp = time.getFullYear()
                + lpad(time.getMonth() + 1)
                + lpad(time.getDate())
                + lpad(time.getHours())
                + lpad(time.getMinutes())
                + lpad(time.getSeconds())
                + lpad(time.getMilliseconds());
            txtFilename += '_' + timestamp;
            var fileItem = '';

            fs.exists(filename, function (exists) {
                if (exists) {
                    handleError('', null);
                } else {
                    fileItem += 'pcap・filename (' + filename + ')\n';
                    fileItem += 'filter (' + filter + ')\n';
                    for (var i = 0; i < filteredPacketList.length; i++) {
                        fileItem += gatherSavedFileData(filteredPacketList[i]);
                    }

                    fs.writeFile(PCAP_DIR + txtFilename + '.txt', fileItem, {encoding:'utf8'},function (err) {
                        if (err) {
                            self.logs.error(err.message);
                        } else {
                            self.logs.info('Successfully saved file.');
                        }
                    });
                }
            });
        });

        function gatherSavedFileData(packet) {
            var str = '';

            var dataLinkLayer = packet.payload ? packet.payload : undefined;
            var networkLayer = packet.payload.payload ? packet.payload.payload : undefined;
            var transportLayer = packet.payload.payload.payload ? packet.payload.payload.payload : undefined;
            var applicationLayer = (transportLayer && packet.payload.payload.payload.data) ? packet.payload.payload.payload.data : undefined;

            var packetData = new Packet();
            packetData.timestamp = packetData.dateFormat(packet.pcap_header.tv_sec, packet.pcap_header.tv_usec);
            str += '<TimeStamp (' + packetData.timestamp + ')>'
                + ((networkLayer && transportLayer) ? (',<IP ヘッダー+TCPヘッダー (' + networkLayer + ')>') : '')
                + (transportLayer ? (',<httpデータSocket・IO情報部 (' + transportLayer + ')>') : '')
                + (applicationLayer ? (',<httpデータQR配信メッセジー部(' + 'test3' + ')>'): '')
                + '\r\n';

            return str;
        }

        var lpad = function lpad(num) {
            if (100 > num && (num%10) > 10) {
                return '0' + lpad(num % 10);
            }
            if (10 > num) {
                return '0' + num;
            }

            return num;
        }
    });
};