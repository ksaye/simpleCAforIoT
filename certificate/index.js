var fs = require('fs');
var camelcase = require('camelcase');
var JSZip = require("jszip");
const {execSync} = require('child_process');

module.exports = async function (context, req) {
    if (req.query.action && (req.query.action == "createCertificate" && req.query.cn) || (req.query.action == "getRootCertificate")) {
        var certOptions = {
            serial: Math.floor(Math.random() * 1000000000),     // not using a sequential serial number
            days: 365 * 100                                     // 100 year certificates
        };

        var rootName = camelcase("RootAuthority");              // default name of our CA, unless given via a parameter
        if (req.query.rootName){
            rootName = req.query.rootName;
        }

        if(!fs.existsSync(rootName + '-publicKey.pem') || !fs.existsSync(rootName + '-privateKey.pem')){     // no CA by that name, creating one.
            execSync('openssl genrsa 2048 > ' + rootName + '-privateKey.pem');
            execSync('openssl req -new -x509 -config config.txt -nodes -days ' + certOptions.days + ' -key ' + rootName + '-privateKey.pem -out ' + rootName + '-publicKey.pem -subj "/CN=' + rootName + '"');
        }

        if (req.query.action == "createCertificate" && req.query.cn){   // create a client cert and return the ZIP file of the private, public and Issuing Authority public key
            var deviceId = req.query.cn;
            if (req.query.iotedge){                                     // for Azure IoT Edge the Certificate must have the CA capability
                execSync('openssl req -newkey rsa:2048 -days ' + certOptions.days + ' -nodes -keyout ' + deviceId + '-privateKey.pem -out ' + deviceId + '-request.pem -subj "/CN=' + deviceId + '"' + 
                ' --addext basicConstraints=critical,CA:TRUE,pathlen:2 --addext keyUsage=keyCertSign,digitalSignature');
            } else {
                execSync('openssl req -newkey rsa:2048 -days ' + certOptions.days + ' -nodes -keyout ' + deviceId + '-privateKey.pem -out ' + deviceId + '-request.pem -subj "/CN=' + deviceId + '"');
            }
            execSync('openssl rsa -in ' + deviceId + '-privateKey.pem -out ' + deviceId + '-privateKey.pem');
            execSync('openssl x509 -req -in ' + deviceId + '-request.pem -days ' + certOptions.days + ' -CA ' + rootName +
                '-publicKey.pem -CAkey ' + rootName + '-privateKey.pem -set_serial ' + certOptions.serial + ' -out ' + deviceId + '-publicKey.pem');

            await new Promise((resolve, reject) => {
                var zipFile = new JSZip();
                zipFile.file(deviceId + '-publicKey.pem', fs.readFileSync(deviceId + '-publicKey.pem'));        // public key
                zipFile.file(deviceId + '-privateKey.pem', fs.readFileSync(deviceId + '-privateKey.pem'));      // private key
                zipFile.file(rootName + '-publicKey.pem', fs.readFileSync(rootName + '-publicKey.pem'));        // public key of the CA
                zipFile.file('certificateIdentity.txt', deviceId);                                              // CN name in the certificate for some clients
                zipFile.generateNodeStream({type:'nodebuffer',streamFiles:true})
                    .pipe(fs.createWriteStream(deviceId + '.zip'))
                    .on('finish', function () {
                        resolve();
                    });
            });

            var data = fs.readFileSync(deviceId + '.zip');
            let headers = {
                'Content-Type': 'application/zip',
                'Content-disposition': 'attachment;filename=' + deviceId + '.zip',
                'Content-Length': data.length
            };
            context.res = {
                status: 200,
                headers: headers,
                isRaw: true,
                body: data
            };

        } else if (req.query.action == "getRootCertificate"){       // return the root certificate Public Key
            var data = fs.readFileSync(rootName + '-publicKey.pem');
            let headers = {
                'Content-Type': 'application/x-x509-ca-cert',
                'Content-disposition': 'attachment;filename=' + rootName + '_cert.pem',
                'Content-Length': data.length
            };
            context.res = {
                status: 200,
                headers: headers,
                isRaw: true,
                body: data
            };
        } 
    } else {
        let headers = {
            'Content-Type': 'text/html'
        };
        context.res = {
            status: 200,
            headers: headers,
            isRaw: false,
            body: '<HTML><HEAD></HEAD><BODY><center><H1>Create x509 Certificate</H1><br>' +
            '<FORM action="./' + context.executionContext.functionName + '">Root CA Name:<input type="text" value="RootAuthority" name="rootName"><br>' +
            'Device Identity:<input type="text" name="cn"><br>' +
            'Is Azure IoT Edge:<input type="checkbox" name="iotedge"><i>subordinate CA setting</i><br>' +
            '<input type="hidden" name="action" value="createCertificate">' +
            '<input type="hidden" name="code" value="' + req.query.code + '">' +
            '<input type="submit" value="Submit Certificate Request">' +
            '</FORM></center></BODY></HTML>'
        };
    }
};
