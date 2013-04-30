#!/usr/bin/perl
# use Net::SMTP;
use strict;
use Socket;

# $Id: checkpolicy.pl,v 1.11 2010/07/01 14:59:00 jbloggs Exp $

# Policy Checker script
# Runs via cron and updated an html page summary.html
# it pulls data from rrdlogs on sysmon and compares the current values with 
# the policy values stored in the file params.
# depending on the value returned and the service is give a BLUE, GREEN, ORANGE, RED flag.
# to state if the service is with in set policy guidelines.

# these values are to be reviewed every 6 months.
# policy violations or changes in the policy colour, initate a e-mail to ABC.
# This page is checked by the support desk in ABC and they e-mail a set group
# if policy colours change.

# Params - file formating:
# based on a single tab delimited txt.
# Easiest to edit in excel (Txt to Columns) and export then export
# 
my $hostname = `hostname`; chomp($hostname);
my $base = '/var/sysmon/www/mrtg/rrdlogs'; # Root specific to stats server
my $debug = 0;
my $usecorrection = 0; # add in Bytes to Megabits conversion 
my ($greppedline,$outfile,$sendto,$eres);
my $test = 0; # testing

my $params = "/usr/local/etc/policy/params";
if ($ARGV[0]) {
  $params = $ARGV[0];
}

my $webpage ='/usr/local/apache/htdocs/summary.html';
$webpage ='/usr/local/apache/htdocs/summary-tg.html' if ($test);

my $prevlog= '/var/log/apache/prevlog.log';
$prevlog= 'prevlog.log' if ($test);

my @emailarray=('');

my $message ="";
#my $message ="This is an automated message\nOriginated from host: $hostname\nBy script: $0\n\n---------------------\n";

my $html='';
my $now=`date '+%Y-%m-%d %H:%M:%S'`;

chomp $now;

open (PARAMS, $params) || die $!;

my $currlog='';

$html.= "<html><head><TITLE>Summary at $now </TITLE><meta http-equiv=\"refresh\" content=\"20\" ></head><body><b>Summary at $now </b><br><table border=\"1\">\n";

$html.= "<tr bgcolor=whitesmoke><td>Domain</td><td>Parameter</td><td><font color=blue>Blue</font></td><td><font color=green>Green</font></td><td><font color=orange>Amber</font></td><td><font color=red>Red</font></td><td><b>Actual</b></td><td>Status</td><td>28 Day Volume</td><td>Last Month Max</td></tr>\n";

while (<PARAMS>) {
	chop;
	# order in param file: 
#Domain  Parameter       Platform        Dir     RRD     Graph   Scale   Blue    Green   Amber   Red     Actual
	my ($Domain,$Parameter,$Platform,$Dir,$RRD,$graph,$scale,$B, $G, $A, $R) = split(/\t/);
	next if $Domain =~ /Domain/i;
	next if !$Domain;
	my $val = &getval($base,$Dir,$RRD, $graph); 
	my ($vol,$max) = &getvol($base,$Dir,$RRD, $scale, $graph);
	
	$vol = sprintf("%0.7g", $vol);

	$val = sprintf("%0.2f", $val);
	my $res = &checkband($B, $G, $A, $R,$val);

	$html.= "<tr><td>";
	$html.= join("</td><td>",$Domain, $Parameter);
	  $html.= "</td><td align=\"right\">";
	$html.= join("</td><td align=\"right\">",$B,$G,$A,$R,'<b>'.$val.'</b>', $res,$vol,$max), "\n";
	  $html.= "</td></tr>\n";
        $currlog.="$Domain,$Parameter,$res\n";
       
	if ($res =~ 'Amber') {
	    $greppedline = `grep "$Domain,$Parameter" $prevlog`;
	    chomp $greppedline;
	    if ($greppedline =~ 'color=green') {
		$message .= "$Domain,$Parameter is now amber, it was green \n";
	    }
	}
       if ($res =~ 'Red') {
	   $greppedline = `grep "$Domain,$Parameter" $prevlog`;
	   chomp $greppedline;
	   if ($greppedline =~ 'color=green') {
	       $message .= "$Domain,$Parameter is now red, it was green \n";
	   }
	   if ($greppedline =~ 'color=orange') {
	       $message .= "$Domain,$Parameter is now red, it was amber \n";
	   }
       }
}
close(PARAMS);
$html.= "</table></body></html>\n"; 
open WEBPAGE ,">$webpage" or die "can't open $outfile: $!";
print WEBPAGE $html;
close WEBPAGE;

open CURRLOG,">$prevlog" or die "can't open $outfile: $!";
print CURRLOG $currlog;
close CURRLOG;

my $sendfrom='do.not.reply@eircom.net';
my $thesubject='Change in ISP Service Status';

if ($message){
    foreach $sendto (@emailarray) {
	$eres=&send_email($sendto,$sendfrom,$thesubject,$message);
    }
}

exit;
###################
#   Sub routines  #
###################

sub checkband {
    my ($B, $G, $A, $R, $val) = @_;
    if (&between($B,$G,$val)) {
	return "<font color=blue>Blue</font>";
    } elsif (&between($G,$A,$val)) {
	return "<font color=green>Green</font>";
    } elsif (&between($A,$R,$val)) {
	return "<font color=orange>Amber</font>";
    } elsif ($val > $R) {
	return "<font color=red>Red</font>";
    }
    return "NA";
}

sub between {
    my ($a, $b, $val) = @_;
    my $t = ($a <= $val && $val <= $b) || ($b<= $val && $val <= $a);
    print "checking $a, $b, $val, $t\n" if $debug;
    return $t;
}

sub getval {
    my ($base,$dir, $rrd, $graph) = @_;
    my $cmd = 'rrdtool fetch '.$base.'/'.$dir.'/'.$rrd.' -s NOW-300 -e NOW  AVERAGE';
    print $cmd,"\n" if $debug;
    open (CMD, $cmd."|") || die $!;
    my (@lines) = <CMD>;
    my $line = @lines[2];
# 1257948300:  5.4436666667e+01  1.1330000000e+01
    my ($time, $val1, $val2) = split(/\s+/,$line);
    close(CMD);
    if ($graph == 1) {
	return $val1;
    } else {
	return $val2;
    }
}

sub getvol {
    my ($base,$dir, $rrd, $scale, $graph) = @_;
    my $tally = 0; my $val = 0; my $max = 0;
    my $cmd = "rrdtool fetch $base\/$dir\/$rrd -s -4W AVERAGE";
    print $cmd,"\n" if $debug;
    open (CMD, $cmd."|") || die $!;
    my (@lines) = <CMD>;

    foreach my $line (@lines) {
	my ($time, $val1, $val2) = split(/\s+/,$line);
	if ($graph == 1) {
	    $val = $val1;
	} else {
	    $val = $val2;
	}
	$tally += $val;
	$max = ($val > $max) ? $val : $max;
    }
    close(CMD);

    my $total=$tally*$scale*7200;
    my $total=sprintf("%.7g",$total);
    $max = sprintf("%d",$max);
    return ($total, $max);
}

sub send_email {
    use vars qw($tmp_rcpt $tmp_from $tmp_subj $tmp_body $port $remote
                $proto $iaddr $paddr $tmp $tmp_full_body);

    $tmp_rcpt = $_[0];
    $tmp_from = $_[1];
    $tmp_subj = $_[2];
    $tmp_body = $_[3];

    my $body_header ="This is an automated message\nOriginated from host: $hostname\nBy script: $0\n\n---------------------\n";

    $remote = "mail00.svc.cra.dublin.eircom.net";
    $port = 25;

    $proto = getprotobyname('tcp');
    $iaddr = inet_aton($remote);
    $paddr = sockaddr_in($port, $iaddr);

    if ( socket (SOCK, PF_INET, SOCK_STREAM, $proto) == 0 )
    {
        print "$0: sub send_email - could not create socket - $! \n";
        exit(1);
    }

    if (connect (SOCK, $paddr) == 0)
    {
        print "$0: sub send_email - could not connect to socket - $!\n";
        exit(1);
    }

    select (SOCK);
    $| = 1;
    select (STDOUT);

    $tmp = <SOCK>;
    if ($tmp !~ /^220/) { print "$0: sub send_email - $! \n"; exit(1); }

    print SOCK "MAIL FROM: $tmp_from \r\n";
    $tmp = <SOCK>;
    if ($tmp !~ /^250/) { print "$0: sub send_email - $! \n"; exit(1); }

    print SOCK "RCPT TO: $tmp_rcpt\r\n";
    $tmp = <SOCK>;
    if ($tmp !~ /^250/) { print "$0: sub send_email - $! \n"; exit(1); }

    print SOCK "DATA\r\n";
    $tmp = <SOCK>;
    if ($tmp !~ /^354/) { print "$0: sub send_email - $! \n"; exit(1); }

    $tmp_full_body =qq[From: $tmp_from
To: $tmp_rcpt
Cc:
Bcc:
Subject: $tmp_subj

$body_header
$tmp_body
];
    print SOCK "$tmp_full_body";

    print SOCK "\r\n.\r\n";
    $tmp = <SOCK>;
    if ($tmp !~ /^250/) { print "$0: sub send_email - $! \n"; exit(1); }
    print SOCK "QUIT\r\n";
    close SOCK;
}
