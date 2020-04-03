const approuter = require('@sap/approuter');
const rp = require('request-promise');
const parseString = require('xml2js').parseString;
const jwtDecode = require('jwt-decode');
const cfenv = require('cfenv');
const uaa_service = cfenv.getAppEnv().getService('uaa_instance');
const dest_service = cfenv.getAppEnv().getService('destination_instance');
const sUaaCredentials = dest_service.credentials.clientid + ':' + dest_service.credentials.clientsecret;
const sDestinationName = 'IAS';
const sEndpoint = "/service/users?mail=";
var ar = approuter();
ar.beforeRequestHandler.use('/getuserinfo', function (req, res, next) {
	if (!req.user) {
		res.statusCode = 403;
		res.end(`Missing JWT Token`);
	} else {
		res.statusCode = 200;
		var decodedJWTToken = jwtDecode(req.user.token.accessToken);
		rp({
			uri: uaa_service.credentials.url + '/oauth/token',
			method: 'POST',
			headers: {
				'Authorization': 'Basic ' + Buffer.from(sUaaCredentials).toString('base64'),
				'Content-type': 'application/x-www-form-urlencoded'
			},
			form: {
				'client_id': dest_service.credentials.clientid,
				'grant_type': 'client_credentials'
			}
		}).then(function (data) {
			const token = JSON.parse(data).access_token;
			return rp({
				uri: dest_service.credentials.uri + '/destination-configuration/v1/destinations/' + sDestinationName,
				headers: {
					'Authorization': 'Bearer ' + token
				}
			});
		}).then(function (data) {
			const oDestination = JSON.parse(data);
			const token = oDestination.authTokens[0];
			return rp({
				method: 'GET',
				uri: oDestination.destinationConfiguration.URL + sEndpoint + req.user.name,
				headers: {
					'Authorization': `${token.type} ${token.value}`
				}
			});
		}).then(function (xmldata) {
			parseString(xmldata, function (err, IASResult) {
				res.end(JSON.stringify({
					name:req.user.name,
					user: req.user,
					decodedJWTToken: decodedJWTToken,
					iasData: IASResult
				}));
			});
		}).catch(function (error) {
			res.end("error: " + JSON.stringify(error));
		});
	}
});
ar.start();