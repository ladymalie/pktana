module.exports = FilterValidation;

function FilterValidation() {
    this._stack = [];
    this._typeList = [];

    this._packets = [];
}


Array.prototype.peek = function () {
    return this[this.length - 1];
}
/**
 * Compiles the filter string to prepare for actual filtering.
 * @method compileFilter
 * @param str {string} The string to be compiled and converted to a proper filter string.
 * @return {type} <description>
 */
FilterValidation.prototype.compileFilter = function (str) {
    _stack = [];
    _typeList = [];
    var result = true;

    if (!str && str.trim().length <= 0) {
        return result;
    }

    var cleanStr = str.trim();
    cleanStr = cleanStr.replace(/\s+/g, '');
    splitString(cleanStr);
    classify(_stack);
    result = checkGrammar();

    /**
     * Split the filter string to prepare for classification of its parts.
     * Makes use of a state machine as parser.
     * @method splitString
     * @param str {string} The string to be parsed.
     * @return {type} <description>
     */
    function splitString(str) {
        var walker = 0;
        var currChar = str.charAt(walker);
        var state = 'start';
        var fString = '';
        var strOpen = false;

        //Loops through each character of the string, classifies
        //and categorizes each subsequent character as part of
        //one string until the character before a space or a
        //character of different classification.
        while (true) {
            switch (state) {
                case ('start'):
                    state = tokenize(currChar);
                    if ('\"' === currChar) {
                        strOpen = true;
                    }
                    fString = fString.concat(currChar);
                    break;
                case ('ope'):
                    state = tokenize(currChar);
                    if (strOpen) {
                        state = 'var';
                        fString = fString.concat(currChar);

                        if ('\"' === currChar) {
                            strOpen = false;
                            _stack.push(fString);
                            fString = '';
                            state = 'start';
                        }
                    } else {
                        if (state === 'ope') {
                            fString = fString.concat(currChar);
                        } else {
                            _stack.push(fString);
                            fString = currChar;
                        }

                        if (!strOpen && '\"' === currChar) {
                            strOpen = true;
                        }
                    }
                    break;
                case ('var'):
                    state = tokenize(currChar);
                    if (strOpen) {
                        state = 'var';
                        fString = fString.concat(currChar);

                        if ('\"' === currChar) {
                            strOpen = false;
                            _stack.push(fString);
                            fString = '';
                            state = 'start';
                        }
                    } else {
                        if (state === 'var') {
                            fString = fString.concat(currChar);
                        } else {
                            _stack.push(fString);
                            fString = currChar;
                        }

                        if (!strOpen && '\"' === currChar) {
                            strOpen = true;
                        }
                    }
                    break;
                case ('log'):
                    state = tokenize(currChar);

                    if (strOpen) {
                        state = 'var';
                        fString = fString.concat(currChar);

                        if ('\"' === currChar) {
                            strOpen = false;
                            _stack.push(fString);
                            fString = '';
                            state = 'start';
                        }
                    } else {
                        if (state === 'log') {
                            fString = fString.concat(currChar);
                        } else {
                            _stack.push(fString);
                            fString = currChar;
                        }

                        if (!strOpen && '\"' === currChar) {
                            strOpen = true;
                        }
                    }
                    break;
                case ('par'):
                    state = tokenize(currChar);
                    _stack.push(fString);
                    fString = currChar;

                    if (!strOpen && '\"' === currChar) {
                        strOpen = true;
                    }
                    break;
            }

            //Go to next character.
            currChar = str.charAt(++walker);

            //Stop when the current character is undefined - end of the string.
            if (!currChar) {
                if (fString && '' !== fString) {
                    _stack.push(fString);
                }
                break;
            }
        }
    };

    /**
     * Determines the classification of a character given a set of default values.
     * @method tokenize
     * @param currChar {string} The character to be classified.
     * @return {string} The classification of the given character.
     */
    function tokenize(currChar) {
        switch (currChar) {
            case ('='):
            case ('<'):
            case ('>'):
            case ('!'):
            case ('~'):
                return 'ope';
            case ('&'):
            case ('|'):
                return 'log';
            case (' '):
                return 'spc';
            case ('('):
            case (')'):
                return 'par';
            default:
                return 'var';
        }
    };

    /**
     * Classify each item of an array based on a standard list of accepted values for each classification.
     * The classification for each item is stored in a different array [_typeList] under the same index.
     * e.g. strArray = ["src.ip", "==" , "192.168.1.121", "||" , "src.ip", "==" , "192.168.1.141"]
     *      _typeList = ["var"  , "ope", "val"          , "log", "var"   , "ope", "val"]
     * @method classify
     * @param strArray {Array} The array of strings to be classified.
     */
    function classify(strArray) {
        // lookup each item in array to check if it is a predefined value and/or is valid.
        var validOpe = ['==', '!=', '>', '<', '<=', '>=', "~="];
        var validLog = ['||', '&&'];
        var validVar = ['src.ip', 'dst.ip', 'src.port', 'dst.port', 'http', 'msg', 'protocol'];
        var validPar = ['(', ')'];
        var not = ['!'];

        for (var i = 0; i < strArray.length; i++) {
            var skipLog = false,
                skipVar = false,
                skipVal = false,
                skipPar = false;

            if (validOpe.indexOf(strArray[i]) !== -1) {
                _typeList.push('ope');
            } else if (not.indexOf(strArray[i]) !== -1) {
                _typeList.push('not');
            } else if (validLog.indexOf(strArray[i]) !== -1) {
                _typeList.push('log');
            } else if (validVar.indexOf(strArray[i]) !== -1) {
                _typeList.push('var');
            } else if (validPar.indexOf(strArray[i]) !== -1) {
                if (strArray[i] === '(') {
                    _typeList.push('oPar');
                } else {
                    _typeList.push('cPar');
                }
            } else {
                _typeList.push('val');
            }
        }
    };

    /**
     * Validates the grammar of the filter.
     * @method checkGrammar
     * @return {boolean} True if the grammar is correct. Else, false.
     */
    function checkGrammar() {
        var correctness = true;
        var traversal = 0;
        var currentDataType = _typeList[traversal];
        var state = 'start';
        var parOpen = false;
        var pairVal = '', pairVar = '', pairOpe = '';
        var parStack = [];
        while (true) {
            switch (state) {
                case ('start'):
                    state = currentDataType;

                    if (state == 'log' || state == 'ope' || state == 'cPar') {
                        state = 'falseEnd';
                    } else if (state == 'val') {
                        pairVal = _stack[traversal];
                    } else if (state == 'var') {
                        pairVar = _stack[traversal];
                    } else if (state == 'oPar') {
                        parOpen = true;
                        parStack.push(_stack[traversal]);
                    }
                    break;
                case ('oPar'):
                    state = currentDataType;

                    if (state == 'oPar') {
                        parStack.push(_stack[traversal]);
                    } else if (state == 'log' || state == 'ope' || state == 'cPar') {
                        state = 'falseEnd';
                    } else if (state == 'val') {
                        pairVal = _stack[traversal];
                    } else if (state == 'var') {
                        pairVar = _stack[traversal];
                    }
                    break;
                case ('cPar'):
                    state = currentDataType;

                    if (state == 'cPar') {
                        if (parStack.length == 0) {
                            correctness = false;
                            return correctness;
                        }
                        parStack.pop();
                    } else if (state == 'log') {
                        state = 'start';
                    } else {
                        state = 'falseEnd';
                    }
                    break;
                case ('var'):
                    state = currentDataType;

                    if (state == 'log') {
                        state = 'start';
                    } else if (state == 'ope') {
                        state = 'varOpe';
                        pairOpe = _stack[traversal];
                    } else if (state == 'cPar') {
                        parStack.pop();
                        state = 'end';
                    } else {
                        state = 'falseEnd';
                    }

                    break;
                case ('val'):
                    state = currentDataType;

                    if (state == 'ope') {
                        state = 'valOpe';
                        pairOpe = _stack[traversal];
                    } else {
                        state = 'falseEnd';
                    }
                    break;
                case ('varOpe'):
                    state = currentDataType;

                    if (state == 'val') {
                        state = 'end';
                        pairVal = _stack[traversal];
                    } else {
                        state = 'falseEnd';
                    }
                    break;
                case ('valOpe'):
                    state = currentDataType;

                    if (state == 'var') {
                        state = 'end';
                        pairVar = _stack[traversal];
                    } else {
                        state = 'falseEnd';
                    }
                    break;
                case ('end'):
                    state = currentDataType;

                    if (state == 'log') {
                        state = 'start';
                        pairVal = pairOpe = pairVar = '';
                    } else if (state == 'cPar') {
                        state = 'end';
                        if (parStack.length == 0) {
                            correctness = false;
                            return correctness;
                        }
                        parStack.pop();
                    } else {
                        state = 'falseEnd';
                    }
                    break;
                case ('not'):
                    state = currentDataType;

                    if (state == 'oPar') {
                        state = 'oPar';
                        parOpen = true;
                        parStack.push(_stack[traversal]);
                    } else if (state == 'var') {
                        state = 'notVar';
                    } else {
                        state = 'falseEnd';
                    }
                    break;
                case ('notVar'): {
                    state = currentDataType;
                    if (state == 'cPar') {
                        if (parStack.length == 0) {
                            correctness = false;
                            return correctness;
                        }
                        state = 'end';
                        parStack.pop();
                    } else if (state == 'log') {
                        state = 'start';
                        pairVal = pairOpe = pairVar = '';
                    } else {
                        state = 'falseEnd';
                    }
                }
                case ('falseEnd'):
                    break;
            }
            // If a variable-value pair is present, validate the value based on the
            // standard of associated variable.
            if ('end' === state) {
                //Prematurely stop the traversal when validation fails.
                if (0 != pairOpe.length || 0 != pairVal.length) {
                    if (!validateValues(pairVar, pairOpe, pairVal)) {
                        correctness = false;
                        return correctness;
                    }
                }
            }

            //Prematurely stop the traversal when an incorrect pattern is found.
            if ('falseEnd' === state) {
                correctness = false;
                break;
            }

            traversal++;
            currentDataType = _typeList[traversal];

            if (!currentDataType) {
                break;
            }
        }

        if (1 == _typeList.length) {
            correctness = ('var' === state);
        } else if (0 == _typeList.length) {
            correctness = true;
        } else if (0 != parStack.length) {
            correctness = false;
        } else {
            correctness = ('notVar' === state || 'var' === state || 'end' === state);
        }

        /**
         * Validates the value against the variable it is paired with.
         * @method validateValues
         * @param variable {string} The variable to be validated.
         * @param ope {string} The operation used by the pair.
         * @param value {string} The value of the variable to be validated.
         * @return {boolean} True if the value is a valid input for the variable.
         */
        function validateValues(variable, ope, value) {
            var result = false;
            var ipRegex = /^(?!0)(?!.*\.$)((1?\d?\d|25[0-5]|2[0-4]\d)(\.|$)){4}$/;
            var strRegex = /"(.| )+"/;
            if ('src.ip' === variable || 'dst.ip' === variable) {
                if ("~=" !== ope) {
                    result = ipRegex.test(value);
                }
            } else if ('src.port' == variable || 'dst.port' == variable) {
                if ("~=" !== ope) {
                    var intTest = ~~Number(value);
                    result = intTest >= 1 && intTest <= 65535 && value === String(intTest);
                }
            } else {
                if ('protocol' === variable) {
                    if ("~=" !== ope) {
                        return strRegex.test(value);
                    }
                } else {
                    if ("~=" === ope) {
                        return strRegex.test(value);
                    }
                }
            }

            return result;
        }

        return correctness;
    };

    return result;
};

/**
 * Apply the filter to the list of _packets received from the server.
 * @method applyFilter
 * @return {array} The filtered array of _packets.
 */
FilterValidation.prototype.applyFilter = function (packets) {
    var result = [];

    //Store the starting indexes of each segment divided by a logical operator.
    var postFix = convertToPostFix();

    var filtered = packets;
    filtered = packets.filter(function (packet) {
        var stack = [];
        for (var index = 0; index < postFix.length; index++) {
            if (!isOperationOrLog(postFix[index])) {
                stack.push(postFix[index]);
            } else {
                var value = '';
                var variable = '';
                var operation = postFix[index];
                if ('&&' === operation) {
                    value = stack.pop();
                    variable = stack.pop();
                    stack.push(value && variable);
                } else if ('||' === operation) {
                    value = stack.pop();
                    variable = stack.pop();
                    stack.push(value || variable);
                } else if ('!' === operation) {
                    stack.push(stack.pop());
                } else {
                    if (!isVariable(variable)) {
                        var tempVar = variable;
                        variable = value;
                        value = tempVar;
                    }
                    stack.push(filterPair_packets(packet, variable, operation, value));
                }
            }
        }

        if (stack.length < 1) {
            return;
        }

        return stack[0];
    });

    /**
    * Converts parsed and tokenized filter string to the Postfix (Reverse Polish) Notation
    * to arrange the array based on the precedence of the operations and groupings.
    * Parentheses are considered but is not included in the output.
    * (e.g.) ((msg~="websocket" && src.ip > 192.168.1.1) || http) || dst.port
    * ¨ [msg, websocket, ~=, src.ip, 192.168.1.1, >, &&, http, ||, dst.port, ||]
    * @method convertToPostfix
    * @return {array} The postfix notation as an array.
    */
    function convertToPostFix() {
        var precedence = { '!': 3, '==': 2, '!=': 2, '~=': 2, '<=': 2, '>=': 2, '<': 2, '>': 2, '&&': 1, '||': 0 };

        var result = [];
        var operatorStack = [];
        for (var index = 0; index < _stack.length; index++) {
            var itemType = _typeList[index];
            var item = _stack[index];
            if ('var' === itemType || 'val' === itemType) {
                result.push(item);
            } else if ('log' === itemType || 'ope' === itemType || 'not' === itemType) {
                var o1 = item;

                var o2 = operatorStack.peek();
                while (isOperationOrLog(o2) && precedence[o1] <= precedence[o2]) {
                    result.push(operatorStack.pop());
                    o2 = operatorStack.peek();
                }

                operatorStack.push(o1);
            } else if ('oPar' === itemType) {
                operatorStack.push(item);
            } else if ('cPar' === itemType) {
                while (operatorStack.peek() !== '(') {
                    var top = operatorStack.pop();
                    result.push(top);

                    if ((0 == operatorStack.length) && top != '(') {
                        return;
                    }
                }

                operatorStack.pop();
            }
        }

        while (operatorStack.length > 0) {
            if (operatorStack.peek() === '('
                || operatorStack.peek() === ')') {
                return;
            }
            result.push(operatorStack.pop());
        };

        return result;
    }

    function isOperationOrLog(token) {
        var opeList = ['==', '!=', '~=', '<=', '>=', '<', '>', '&&', '||', '!'];

        return (opeList.indexOf(token) != -1)
    }

    function isVariable(token) {
        var opeList = ['src.ip', 'src.port', 'dst.ip', 'dst.port', 'msg', 'protocol', 'http'];

        return (opeList.indexOf(token) != -1)
    }

    /**
     * Determines if a packet contains the given variable and if its corresponding value
     * matches the filter value.
     * @method filterPair_packets
     * @param packet {Object} The packet object considered.
     * @param variable {string} The filter string equivalent of the packet object member.
     * @param operation {string} The comparison operator between the variable and the value.
     * @param value {string} The value to match the packet object member's value with.
     * @return {boolean} True if packet satisfies the condition.
     */
    function filterPair_packets(packet, variable, operation, value) {
        var result = false;
        // Search packet for existence of each variable and equality of the value
        // associated to each variable.
        var linkLayer = packet.payload;
        var networkLayer = packet.payload.payload;
        var transportLayer = packet.payload.payload.payload;
        if ("src.ip" === variable) {
            result = networkLayer.saddr &&
                     compareValues(networkLayer.saddr.toString('ascii'), operation, value);
        } else if ("dst.ip" === variable) {
            result = networkLayer.daddr &&
                     compareValues(networkLayer.daddr.toString('ascii'), operation, value);
        } else if ("src.port" === variable) {
            result = transportLayer && transportLayer.sport &&
                compareValues(transportLayer.sport, operation, value);
        } else if ("dst.port" === variable) {
            result = transportLayer && transportLayer.dport &&
                compareValues(transportLayer.dport, operation, value);
        } else if ("http" === variable) {

        } else if ("msg" === variable) {

        } else if ("protocol" === variable) {

        }

        return result;
    };

    function compareValues(actual, operation, expected) {
        if ("==" === operation) {
            return actual == expected;
        } else if ("<=" === operation) {
            return actual <= expected;
        } else if ("<" === operation) {
            return actual < expected;
        } else if (">=" === operation) {
            return actual >= expected;
        } else if (">" === operation) {
            return actual > expected;
        } else if ("!=" === operation) {
            return actual != expected;
        }
    }

    /**
     * Determines if a packet contains a specified variable.
     * @method filter_packets
     * @param packet {Object} The packet object considered.
     * @param variable {string} The filter string equivalent of the packet object member.
     * @return {boolean} True if packet has the given variable as its member.
     */
    function filter_packets(packet, variable) {
        var result = false;

        var linkLayer = packet.payload;
        var networkLayer = packet.payload.payload;
        var transportLayer = packet.payload.payload.payload;
        // Search packet for existence of variable only.
        if ("src.ip" === variable) {
            result = ('undefined' === typeof linkLayer.shost);
        } else if ("dst.ip" === variable) {
            result = ('undefined' === typeof linkLayer.dhost);
        } else if ("ip" === variable) {
            result = ('undefined' === typeof linkLayer.dhost)
                        || ('undefined' === typeof linkLayer.dhost);
        } else if ("src.port" === variable) {
            result = transportLayer && transportLayer.sport;
        } else if ("dst.port" === variable) {
            result = transportLayer && transportLayer.dport;
        } else if ("http" === variable) {

        } else if ("msg" === variable) {
            result = 'undefined' === transportLayer.data;
        } else if ("protocol" === variable) {
            result = true;
        }

        return result;
    };
    return filtered;
};