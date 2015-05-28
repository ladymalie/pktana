var fs = require('fs');
var util = require('util');

module.exports = Router;


function Router(logger) {

    if (!logger) {
        // throw error
    }

    this.logs = logger.getLogger('router');
    // set other variables for Router
}

Router.prototype.set = function (app) {
    var self = this;
    // Configurations for express application here

    app.get('/pcap', function (req, res) {
        self.logs.info('loading UI');
        res.contentType('text/html');
        res.sendFile(__dirname + '/views/mainScreen.html');
    });

    app.get('/js/jquery-1.11.3.min.js', function (req, res) {
        self.logs.info('loading jquery-1.11.3.min.js');
        res.contentType('js');
        res.sendFile(__dirname + '/public/jquery-1.11.3.min.js');
    });

    app.get('/js/jquery-ui-1.10.4.min.js', function (req, res) {
        self.logs.info('loading jquery-1.11.3.min.js');
        res.contentType('js');
        res.sendFile(__dirname + '/public/jquery-ui-1.10.4/ui/minified/jquery-ui.min.js');
    });

    app.get('/js/datatables-1.10.7.min.js', function (req, res) {
        self.logs.info('loading datatables-1.10.7.min.js');
        res.contentType('js');
        res.sendFile(__dirname + '/public/DataTables-1.10.7/media/js/jquery.dataTables.min.js');
    });

    app.get('/js/colreorder-1.1.3.min.js', function (req, res) {
        self.logs.info('loading colreorder-1.1.3.min.js');
        res.contentType('js');
        res.sendFile(__dirname + '/public/DataTables-1.10.7/extensions/ColReorder/js/dataTables.colReorder.min.js');
    });

    app.get('/js/scroller-1.2.2.min.js', function (req, res) {
        self.logs.info('loading scroller-1.2.2.min.js');
        res.contentType('js');
        res.sendFile(__dirname + '/public/DataTables-1.10.7/extensions/Scroller/js/dataTables.scroller.min.js');
    });
    //app.get('/js/client_load_test.js', function (req, res) {
    //    self.logs.info('loading client_load_test.js');
    //    res.contentType('js');
    //    res.sendFile(__dirname + '/client_load_test.js');
    //});

    //app.get('/parse-client.js', function (req, res) {
    //    self.logs.info('loading parse-client.js');
    //    res.contentType('js');
    //    res.sendFile(__dirname + '/parse-client.js');
    //});

    return app;
};