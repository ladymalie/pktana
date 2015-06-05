var node_http = require('http');
var io = require('socket.io');
var pcap = require('pcap'),
    wsParser = require('pcap/decode/websocket');
var fs = require('fs');
var util = require('util');

var Packet = require('./packet');
var Filter = require('./filter');


module.exports = Server;

/*
 * The default directory where all the pcap data is stored.
 */
var PCAP_DIR = __dirname + '/../pcapDir/'

/**
 * The path to the config.json file.
 */
var CONFIG_PATH = __dirname + '/config/config.json';

/**
 * The path to the language config.json file.
 */
var LOCALE_CONFIG_PATH = __dirname + '/config/lang-en.json';

/*
 * The function which serves as the constructor for the module.
 * @method Server
 * @param logger {object} The instance of the logging module.
 */
function Server(logger) {
    if (!logger) {
        // handle error
    }

    this.logs = logger.getLogger('server');
    this.logs.setLevel('ERROR');
};

/**
 * Start up the node server.
 * @method start
 * @param app {object} The express application that will be included
 *                     in the server.
 *
 */
Server.prototype.start = function (app) {
    var config, langConfig;
    var self = this;
    self.app = app;

    try {
        config = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
    } catch (e) {
        self.logs.error('GWSV028 failed to read config file[' + CONFIG_PATH + ']. reason: ' + e.message);
        return;
    }

    try {
        langConfig = JSON.parse(fs.readFileSync(LOCALE_CONFIG_PATH, 'utf8'));
    } catch (e) {
        self.logs.error('GWSV028 failed to read config file[' + LOCALE_CONFIG_PATH + ']. reason: ' + e.message);
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
        self.logs.info('Client [' + socket.id + '] has connected.');

        var sockets = socketIO.sockets;

        var rawPacketList = [];

        var decodedPacketList = [];
        var filteredPacketList = [];

        var errorList = [];

        var origPacketList = [];
        var packetList = [];
        var counter = 0;
        var dateNow = Date.now();

        // Listen to a 'disconnect' event emitted by [socket].
        socket.on('disconnect', function (reason) {
            self.logs.info('Client [' + socket.id + '] has disconnected.');
        });

        socket.on('error', function (err) {
            self.logs.error(err.message);
            self.logs.info('Disconnecting client [' + socket.id + ']');
        });

        /**
         * A sample event to be used as basis for other events.
         * @method sample event
         * @parameteram data {object} The data passed by the client.
         * @param resolveError {function} The callback that resolves existing errors.
         *
         */
        socket.on('_sampleEvent' /*custom events start with _*/, function (data, resolveError) {
            console.log(data);

            var err = { "errList": [] };

            // if not the expected data / value / behaviour
            // err["errList"].push({"error_ID" : "error_message"});
            console.log(data);
            //err["errList"].push({ "ERRXXX": "No error!" });
            resolveError(err);
            if (err[errList].length == 0) {
                sockets.emit('_clientEvent', 'data to emit');
                //return if necessary because it will continue running to the next
                //lines of code.
            }
        });

        socket.on('_getFileList', function(resolveError) {
            var files = getFileList();
            var jsonFileList = {0 : '-------------'};
            for (var i = 1; i <= files.length; i++) {
                jsonFileList[i] = files[i - 1];
            }

            if (files.length > 0) {
                sockets.emit('_showFileList', jsonFileList);
                resolveError(handleError(undefined, undefined));
            } else {
                resolveError(handleError('ERR000', langConfig["ERR000"]));
            }
        });

        /*
         * Gets a list of pcap files from the default directory. @method
         * getFileList @returns filtered {array} An array of filenames in the
         * said directory.
         */
        function getFileList() {
            self.logs.info('Reading ' + PCAP_DIR);

            var files = fs.readdirSync(PCAP_DIR);
            var filtered = files.filter(function(file) {
                return /\.pcap$/i.test(file);
            });
            return filtered;
        }

        socket.on('_start', function(filename, resolveError) {
            self.logs.info('Reading file ' + filename);
            var pcap_session;
            var tcp_tracker;
            counter = 0;
            var pcap_file = PCAP_DIR + filename;

            var currSrc, currDst, key;

            self.logs.info('PCAPFILE ' + pcap_file);
            try {
                fs.statSync(pcap_file);
                pcap_session = pcap.createOfflineSession(pcap_file, 'ip');
            } catch (error) {
                if (error.code === 'ENOENT') {
                    resolveError(handleError('ERR002', langConfig["ERR002"]));
                } else {
                    resolveError(handleError('ERR001', langConfig["ERR001"]));
                }
                return;
            }

            rawPacketList = [];
            decodedPacketList = [];
            errorList = [];
            origPacketList = [];
            packetList = [];

            tcp_tracker = new pcap.TCPTracker();

            var protocol; var message;

            // Listen to a 'packet' event emmitted by [pcap_session].
            // Here we can do things to the packet data through the callback function.
            pcap_session.on('packet', function (packet) {
                // Decode the packets based on its done by [pcap] automatically.
                var fpacket = pcap.decode(packet);
                var packetData = gatherTableDisplayData(counter, fpacket);

                var networkLayer = fpacket.payload.payload;
                var transportLayer = networkLayer.payload;

                if (networkLayer && transportLayer) {
                    currDst = networkLayer.daddr.toString('ascii') + ':'+ transportLayer.dport;
                    currSrc = networkLayer.saddr.toString('ascii') + ':'+ transportLayer.sport;
                }

                if (currSrc < currDst) {
                    key = currSrc + "-" + currDst;
                } else {
                    key = currDst + "-" + currSrc;
                }
                // Track a tcp packet for its message.
                // TODO: To be implemented yet.
                tcp_tracker.track_packet(fpacket);
                var packetProtocol = packetData.protocol;
                if (protocol) {
                    packetProtocol = protocol;
                    protocol = undefined;
                }
                var packetMessage = packetData.message;
                if (message) {
                    packetMessage = message.substr(0, 30);
                    message = undefined;
                }
                packetList.push([packetData.counter, packetData.timestamp, packetData.srcIP, packetData.dstIP, packetProtocol, packetData.length, packetData.info, packetMessage]);
                var buf = new Buffer(packet.buf);
                var cap_len = fpacket.pcap_header.caplen;
                rawPacketList.push({ "data": buf, "length": cap_len });
                decodedPacketList.push(fpacket);

                // Emit an event 'packet' to the client.
                socketIO.sockets.emit('packet');

                counter++;
            });

            // Listen to a 'complete' event emitted by [pcap_session].
            // 'complete' is emitted once all packets in a session is read.
            pcap_session.on('complete', function () {
                origPacketList = packetList;
                filteredPacketList = decodedPacketList;

                // Emit a 'complete' event to the client.
                self.logs.info('Packet load completed in: ' + (Date.now() - dateNow) + ' ms');
                socketIO.sockets.emit('complete', packetList);
                console.log(sessions);
            });

            var sessions = {}; //temporary

            tcp_tracker.on('session', function (session) {
                if (!sessions[key]) {
                    sessions[key] = [];
                }
                sessions[key].push(counter);
                //var parser = new wsParser();
                session.on('data recv', function (session, data) {
                    message = data.toString();
                    if (session.isUpgraged) {
                        protocol = session.protocol;
                        var ws = decodeWebsocket(data);
                        message = ws.message;
                    }
                    
                    if (data.toString().indexOf('Connection: Upgrade') > -1 && 
                        data.toString().indexOf('Upgrade: websocket') > -1) {
                        session.isUpgraged = true;
                        session.protocol = 'Websocket';
                    }
                });

                session.on('data send', function (session, data) {
                    message = data.toString();
                    if (session.isUpgraged) {
                        protocol = session.protocol;
                        var ws = decodeWebsocket(data);
                        message = ws.message;
                    }
                });
            });

            resolveError(handleError(undefined, undefined));
        });

        function decodeWebsocket(data) {
            var result = {};
            var buf = new Buffer(data);
            var offset = 0;
            var hex = buf.toString('hex');
            var byte_one = hex.substr(offset, 2); offset += 2;
            var byte_two = hex.substr(offset, 2); offset += 2;
            var payload_len = 0;
            var fin_flag = false;
            var mask_flag = false;
            var mask = '';

            var fin = parseInt(byte_one, 16).toString(2).substr(0, 1);
            var opcode = parseInt(byte_one, 16).toString(2).substr(4, 4);
            result.opcode = opcode;

            fin = (fin == 1) ? true : false;
            result.fin = fin;

            var dec_two = parseInt(byte_two, 16).toString(10);
            payload_len = dec_two;
            if (payload_len > 127) {
                mask_flag = true;
                payload_len = dec_two & 127;
            }
                
            if (payload_len == 126) {
                payload_len = parseInt(hex.substr(offset, 4), 16).toString(10);
                offset += 4;
                
            } else if (payload_len == 127) {
                payload_len = parseInt(hex.substr(offset, 16), 16).toString(10);
                offset += 16;
            }

            result.payload_len = payload_len;
            result.masked = mask_flag;

            var message;
            if (mask_flag) {
                mask = hex.substr(offset, 8);
                result.maskKey = mask;
                offset += 8;
                message = ''; //Apply masking key with hex.substr(offset, payload_len * 2)
            }
            message = new Buffer(hex.substr(offset, payload_len * 2), 'hex').toString('utf8');
            result.message = message;
            return result;
        }

        function handleError(errID, errMsg) {
            var err = {"errList" : [], "success" : ""};

            if (errID) {
                err["errList"].push({'errID' : errID, 'errMsg' : errMsg});
            } else {
                if (errMsg) {
                    err["success"] = errMsg;
                }
            }

            return err;
        };

        function gatherTableDisplayData(counter, decoded_packet) {
            var packetData = new Packet();

            var networkLayer = decoded_packet.payload.payload;
            var transportLayer = networkLayer.payload;
            packetData.counter = counter;
            packetData.timestamp = packetData.dateFormat(decoded_packet.pcap_header.tv_sec, decoded_packet.pcap_header.tv_usec);
            if (networkLayer) {
                if (networkLayer.saddr && networkLayer.saddr.o1) {
                    packetData.srcIP = networkLayer.saddr.toString('ascii');
                    packetData.dstIP = networkLayer.daddr.toString('ascii');
                }
        		self.logs.info('networkLayer:  ' + networkLayer);
                    	
        		if(networkLayer.protocol.toString()== '6'){
        		    packetData.protocol = 'TCP';

        		    if (transportLayer && (transportLayer.sport === 80 || transportLayer.dport === 80) && transportLayer.data_bytes > 0) {
        		        packetData.protocol = 'HTTP';
        		    }
        		}
        		else if(networkLayer.protocol.toString()== '17'){
                                packetData.protocol='UDP';
                        }
        		else{
        			  packetData.protocol='Something Else';
        		}

        		packetData.length=decoded_packet.pcap_header.len;
                // packetData.info='tv_sec : '+decoded_packet.pcap_header.tv_sec +' tv_usec : '+ decoded_packet.pcap_header.tv_usec + ' caplen : ' +decoded_packet.pcap_header.caplen;


        		packetData.info='sport : '+ transportLayer.sport + ' dport : '+ transportLayer.dport + ' length : ' + transportLayer.length + ' checksum : '+transportLayer.checksum;
                self.logs.info('Transport Layer sport:  ' + transportLayer.sport);
                self.logs.info('Transport Layer dport:  ' + transportLayer.dport);
                // self.logs.info('Transport Layer data:  ' + transportLayer.data.toString());

	       }
	   
            return packetData;
        }

        socket.on('validate', function (control, filter) {
            self.logs.info('Validating input:  ' + filter + 'for ' + control);
            
            var valid = true;
            if ('txtFilter' === control)  {
                var filterValidator = new Filter(self.logs);
                valid = filterValidator.compileFilter(filter);
            } else if ('cmbFileList' === control) {
                valid = getFileList().indexOf(filter) != -1;
            }

            socketIO.sockets.emit('validated', valid);
        });

        socket.on('filter', function (filter, resolveError) {
            self.logs.info(filter);

            var filterValidator = new Filter(self.logs);
            var valid = filterValidator.compileFilter(filter);
            
            self.logs.info('Compile Filter Result : '+ filter);
            if (valid) {
                var filteredList = filterValidator.applyFilter(decodedPacketList);
                filteredPacketList = filteredList;
                packetList = [];
                for (var i = 0; i < filteredList.length; i++) {
                    var packetData = gatherTableDisplayData(i, filteredList[i]);
                    packetList.push([packetData.counter, packetData.timestamp, packetData.srcIP, packetData.dstIP,packetData.protocol,packetData.length,packetData.info,packetData.message]);
                }

                if (0 == filter.length) {
                    packetList = origPacketList;
                    filteredPacketList = decodedPacketList;
                }
				resolveError(handleError('', ''));
                socketIO.sockets.emit('filtered', packetList);
            }else{
                resolveError(handleError('ERR001', 'Invalid Syntax'));
    	    }
            
        });

        socket.on('_saveFile', function (filename, filter, resolveError) {
            self.logs.info('Saving packets to file ' + filename + '.txt');

            var txtFilename = filename.replace('.pcap', '');
            var time = new Date();

            var timestamp = time.getFullYear()
                + lpad(time.getMonth() + 1)
                + lpad(time.getDate())
                + lpad(time.getHours())
                + lpad(time.getMinutes())
                + lpad(time.getSeconds());
            txtFilename += '_' + timestamp;
            var fileItem = '';

            fs.exists(filename, function (exists) {
                if (exists) {
                    resolveError(handleError('ERR004', 'Filename already exists.'));
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

                    resolveError(handleError(undefined, 'Successfully saved file.'));
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
                + (applicationLayer ? (',<httpデータQR配信メッセジー部(' + 'test3' + ')>') : '')
                + '\r\n';

            return str;
        }

        function lpad(num) {
            if (10 > num) {
                return '0' + num;
            }

            return num;
        }

        socket.on('_getDecodedPacket', function (tabIndex, packetIndex, resolveError) {
            if (0 == tabIndex) {
                hexaDecimalFormat(packetIndex, resolveError);
            } else {
                readableFormat(packetIndex, resolveError);
            }
        });

        function hexaDecimalFormat(packetIndex, resolveError) {
            var currPacket = rawPacketList[packetIndex];
            var packetData = currPacket["data"].toString('hex').slice(0, currPacket["length"] * 2);
            var hexDataTable = [];
            var row = "";
            var ctr = 0;
            var rowCount = 0;

            for (var i = 0; i < packetData.length; i += 2) {
                if (ctr == 16) {
                    var str = "" + rowCount;
                    rowCount += 10;
                    var pad = "0000";
                    var res = pad.substring(0, pad.length - str.length) + str;
                    hexDataTable.push({ "rowNum": res, "rowData": row });
                    row = '';
                    ctr = 0;
                } else if (ctr == 8) {
                    row += '|';
                }

                row += packetData[i] + '' + packetData[i + 1] + ' ';
                ctr++;

                if (i + 2 == packetData.length) {
                    var str = "" + rowCount++;
                    var pad = "0000";
                    var res = pad.substring(0, pad.length - str.length) + str;
                    hexDataTable.push({ "rowNum": res, "rowData": row });
                }

            }
            resolveError(handleError(undefined, undefined));
            sockets.emit('_displayRawPacket', hexDataTable);
        }

        function readableFormat(packetIndex, resolveError) {
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
                    formattedString += 'Protocol: [' + 'unknown' + '], ';
                    formattedString += 'src port: [' + transportLayer.sport + '], ';
                    formattedString += 'dst port: [' + transportLayer.dport + ']';
                }
            }
            resolveError(handleError(undefined, undefined));
            sockets.emit('_displayDecodedPacket', formattedString);
        }

    });
};
