var fs = require('fs');
var url = require('url');
var http = require('http');
var querystring = require('querystring');
var db = []; //database
var path = require('path');
//---------------------------------------------------------------------------------------------
// function gửi yêu cầu(response) từ phía server hoặc nhận yêu cầu (request) của client gửi lên
function requestHandler(request, response) {
    // Giả sử địa chỉ nhận được http://192.168.1.7:8000/update?heart=30&step=40
    var uriData = url.parse(request.url);
    var pathname = uriData.pathname; // /update?
    var query = uriData.query; 
    var queryData = querystring.parse(query); 
    //-----------------------------------------------------------------------------------------
    if (pathname == '/update') {
        var newData = {
            heart: queryData.heart,
            step: queryData.step,
            calo: queryData.calo,
            time: new Date() 
        };
        db.push(newData);
        console.log(newData);
        response.end();
        //-----------------------------------------------------------------------------------------
    } else if (pathname == '/get') {
    
        response.writeHead(200, {
            'Content-Type': 'application/json',
            
        });
        
        response.end(JSON.stringify(db));
        db = [];
        
        //-----------------------------------------------------------------------------------------
    } 
    
    else {
        fs.readFile('./index.html', function (error, content) {
            response.writeHead(200, {
                'Content-Type': 'text/html',
                
            });
            response.end(content);
        });
        
    }
    //-----------------------------------------------------------------------------------------
}
var server = http.createServer(requestHandler);
server.listen(3000); 
console.log('Server listening on port 3000');