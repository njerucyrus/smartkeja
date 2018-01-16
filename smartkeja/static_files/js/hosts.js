
function getBaseHostUrl() {
   var live=true;
   var host = 'http://localhost:8000';
   if (live){
        host = 'https://smartkeja.herokuapp.com'
   }

   return host
}