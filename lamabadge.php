<?php
#Badge is often loaded through a proxy (i.e. Github's camo), prevent caching at all costs as we want to count hits
header("Cache-control: no-cache");
header("Expires: Mon, 15 Dec 1982 19:21:20 GMT");
$etag = "";
for ($i = 0; $i != 16; ++$i) {
        $etag .= chr(mt_rand(0, 255));
}
$etag = bin2hex($etag);
header("Etag: \"$etag\"");
header("Pragma: no-cache");
header('Content-type: image/svg+xml');

$fp = fopen("lamabadge.svg","r");
echo fread($fp, filesize("lamabadge.svg"));
fclose($fp);

#We just pass an ID like 
#http://applejack.science.ru.nl/lamabadge.php/colibri-core 
#and gather the stats from the Apache access log

?>
