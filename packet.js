module.exports = Packet;
function Packet() {
    this.counter;
    this.srcIP;
    this.dstIP;
    this.timestamp;
    this.protocol;
    this.message;
    this.info;
};

Packet.prototype.dateFormat = function (timestamp, usec) {
    var ms = timestamp * 1000;
    var date = new Date(ms);
    return date.getFullYear() +
        '-' + lpad(date.getMonth() + 1) +
        '-' + lpad(date.getDate()) +
        ' ' + lpad(date.getHours()) +
        ':' + lpad(date.getMinutes()) +
        ':' + lpad(date.getSeconds()) +
        (usec / 1000000).toFixed(6).slice(1, 8);
}

function lpad(num) {
    if (10 > num) {
        return '0' + num;
    }

    return num;
}