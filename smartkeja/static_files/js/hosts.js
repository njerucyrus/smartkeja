
function getBaseHostUrl() {
   var live=false;
   var host = 'http://localhost:8000';
   if (live){
        host = ''
   }

   return host
}