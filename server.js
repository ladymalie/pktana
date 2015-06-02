var node_http = require('http');
var io = require('socket.io');
var pcap = require('pcap');
var fs = require('fs');
var util = require('util');


module.exports = Server;

/**
 * The path to the config.json file.
 */
var CONFIG_PATH = __dirname + '/config/config.json';

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
        config = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
    } catch (e) {
        self.logs.error('GWSV028 failed to read config file[' + CONFIG_PATH + ']. reason: ' + e.message);
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
         * @param data {object} The data passed by the client.
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

    });
};