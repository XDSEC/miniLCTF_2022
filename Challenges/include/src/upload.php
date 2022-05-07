<?php
error_reporting(0);
spl_autoload_register();
set_include_path("./upload");
class user{
    var $usergroup='Tourist';
}
setcookie("user",base64_encode(serialize(new user())));

$deny_ext = array("ph","htm","ini","js","jtml", "as","cer", "swf", "htaccess");
$file="file".md5($_FILES['file']['name']).'.'.pathinfo($_FILES['file']['name'])['extension'];
chdir("upload");

$user = unserialize(base64_decode($_COOKIE['user']));
if ($user->usergroup!='Lteam') {
    die("Only members of Lteam can use it.");
}
elseif ($_FILES["file"]["error"] > 0) {
    echo "Error！" . "<br>";
}
elseif(file_exists($file)){
    die("文件已存在！"."./upload/".$file);
}
else{ 
    $file_name = trim($_FILES['file']['name']);
    if (stristr($file_name, $deny_ext)) {
        die("hacker!");
    } else {
        $temp_file = $_FILES['file']['tmp_name'];
        $path = "./".$file;
        $pathshow = "./upload/".$file;
        $info = "filename: " . $_FILES["file"]["name"] .";". "<br>". "type: " . $_FILES["file"]["type"] .";". "<br>"."size: " . ($_FILES["file"]["size"] / 1024) . " kB".";". "<br>"."path:" . $pathshow;

        if (move_uploaded_file($temp_file, $path)) {
            echo "上传成功！". "<br>";
            die($info);
        }
    }
}
