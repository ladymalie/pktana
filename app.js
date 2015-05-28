var io = require('socket.io');
var fs = require('fs');
var pcap = require('pcap');
var util = require('util');
var node_http = require('http');
var log4js = require('log4js');
var express = require('express');
var Router = require('./route');
var Server = require('./server');

app = express();


var router = new Router(log4js);
router.set(app);

var server = new Server(log4js);
(function start() {
    server.start(app);
})();
