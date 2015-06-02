var fs = require('fs');
var util = require('util');

module.exports = Router;


function Router(logger) {

    if (!logger) {
        // throw error
    }

    this.logs = logger.getLogger('router');
}

Router.prototype.set = function (app) {
    var self = this;
    // Configurations for express application here

    app.get('/pcap', function (req, res) {
        self.logs.info('Loading mainScreen.html');
        res.contentType('text/html');
        res.sendFile(__dirname + '/views/mainScreen.html');
    });

    app.get('/js/jquery-1.11.3.min.js', function (req, res) {
        self.logs.info('loading jquery-1.11.3.min.js');
        res.contentType('js');
        res.sendFile(__dirname + '/public/jquery-1.11.3.min.js');
    });

    return app;
};