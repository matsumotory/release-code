/*
// -------------------------------------------------------------------
// mod_vlimit 
//     Control the number of references from the same IP address to file access
//          or the number of references from the same file name to file access
//
//     By matsumoto_r (MATSUMOTO Ryosuke) Sep 2010 in Japan
//
// Date     2010/09/21
// Version  1.00
//
// change log
//  2010/09/21 0.10 SHM_DATA files count on shared memory add matsumoto_r
//  2010/09/21 0.20 vlimit_response()_end create matsumoto_r
//  2010/09/22 0.21 make_ip_slot_list() create matsumoto_r
//  2010/09/22 0.22 make_file_slot_list() create matsumoto_r
//  2010/09/22 0.90 vlimit_mutex add matsumoto_r
//  2010/12/24 1.00 ServerAlias routine add matsumoto_r
// -------------------------------------------------------------------

// -------------------------------------------------------------------
// How To Compile
// [Use DSO]
// apxs -i -c mod_vlimit.c
//
// <add to  httpd.conf>
// LoadModule vlimit_module modules/mod_vlimit.so
//
// -------------------------------------------------------------------

// -------------------------------------------------------------------
// How To Use
//
// VlimitIP <number of MaxConnectionsPerHost to DocumentRoot> (RealPath of DocumentRoot)
//
//      <Directory "/www/hoge/huga/001">
//           VlimitIP 5
//      </Directory>
//
//
//      <Files "a.txt">
//          VlimitIP 10 /www/hoge/huga/001/a.txt
//      </Files>
//
//      <FilesMatch "^.*\.txt$">
//          VlimitIP 10
//      </Files>
//
//
// VlimitFile <number of MaxConnectionsPerFile> (RealPath of DocumentRoot)
//
//      <Files "a.txt">
//          VlimitFile 10 /www/hoge/huga/001/a.txt
//      </Files>
//
//      <FilesMatch "^.*\.txt$">
//          VlimitFile 10
//      </Files>
//
// Check Debug Log
//      touch /tmp/VLIMIT_DEBUG
//      less /var/log/syslog
//
// Check Module Access Log
//      touch /tmp/VLIMIT_LOG
//      less /tmp/mod_vlimit.log
//
// Check Current File Counter Lists
//      touch /tmp/VLIMIT_FILE_STAT
//      cat /tmp/vlimit_file_stat.list
//      
//      - recreate lists
//          rm /tmp/vlimit_file_stat.list  
//          cat /tmp/vlimit_file_stat.list
//
// Check Current IP Counter Lists
//      touch /tmp/VLIMIT_IP_STAT
//      cat /tmp/vlimit_ip_stat.list
//      
//      - recreate lists
//          rm /tmp/vlimit_ip_stat.list  
//          cat /tmp/vlimit_ip_stat.list
//
// mod_vlimit.log sample
// [Fri Mar 11 11:54:48 2011] pid=[28734] name=[172.16.71.46] client=[172.16.71.46] RESULT:  OK INC ip_count: 1/5 file_count: 0/0 file=[/var/www/html/32.php]
// [Fri Mar 11 11:54:48 2011] pid=[28734] name=[172.16.71.46] client=[172.16.71.46] RESULT: END DEC ip_count: 0/5 file_count: 0/0 file=[/var/www/html/32.php]
// [Fri Mar 11 11:54:48 2011] pid=[28648] name=[172.16.71.46] client=[172.16.71.46] RESULT:  OK INC ip_count: 1/5 file_count: 0/0 file=[/var/www/html/33.php]
// [Fri Mar 11 11:54:48 2011] pid=[28580] name=[172.16.71.46] client=[172.16.71.46] RESULT:  OK INC ip_count: 2/5 file_count: 0/0 file=[/var/www/html/33.php]
// [Fri Mar 11 11:54:48 2011] pid=[28402] name=[172.16.71.46] client=[172.16.71.46] RESULT:  OK INC ip_count: 3/5 file_count: 0/0 file=[/var/www/html/33.php]
// [Fri Mar 11 11:54:48 2011] pid=[28532] name=[172.16.71.46] client=[172.16.71.46] RESULT:  OK INC ip_count: 4/5 file_count: 0/0 file=[/var/www/html/33.php]
// [Fri Mar 11 11:54:48 2011] pid=[28648] name=[172.16.71.46] client=[172.16.71.46] RESULT: END DEC ip_count: 3/5 file_count: 0/0 file=[/var/www/html/33.php]
// [Fri Mar 11 11:54:48 2011] pid=[28776] name=[172.16.71.46] client=[172.16.71.46] RESULT:  OK INC ip_count: 4/5 file_count: 0/0 file=[/var/www/html/33.php]
// [Fri Mar 11 11:54:48 2011] pid=[28653] name=[172.16.71.46] client=[172.16.71.46] RESULT:  OK INC ip_count: 5/5 file_count: 0/0 file=[/var/www/html/34.php]
// [Fri Mar 11 11:54:48 2011] pid=[28764] name=[172.16.71.46] client=[172.16.71.46] RESULT: 503 INC ip_count: 6/5 file_count: 0/0 file=[/var/www/html/34.php]
// [Fri Mar 11 11:54:48 2011] pid=[28544] name=[172.16.71.46] client=[172.16.71.46] RESULT: 503 INC ip_count: 7/5 file_count: 0/0 file=[/var/www/html/34.php]
// [Fri Mar 11 11:54:48 2011] pid=[28557] name=[172.16.71.46] client=[172.16.71.46] RESULT: 503 INC ip_count: 8/5 file_count: 0/0 file=[/var/www/html/34.php]
// [Fri Mar 11 11:54:48 2011] pid=[28778] name=[172.16.71.46] client=[172.16.71.46] RESULT: 503 INC ip_count: 9/5 file_count: 0/0 file=[/var/www/html/34.php]
// [Fri Mar 11 11:54:48 2011] pid=[28580] name=[172.16.71.46] client=[172.16.71.46] RESULT: END DEC ip_count: 8/5 file_count: 0/0 file=[/var/www/html/33.php]
// 
// vlimit_file_stat.list sample
// [Fri Mar 11 11:51:15 2011] slot=[2] filename=[20.php] counter=[10]
// [Fri Mar 11 11:51:15 2011] slot=[3] filename=[12.php] counter=[7]
// [Fri Mar 11 11:51:15 2011] slot=[4] filename=[23.php] counter=[10]
// [Fri Mar 11 11:51:15 2011] slot=[5] filename=[24.php] counter=[10]
// [Fri Mar 11 11:51:15 2011] slot=[6] filename=[4.php] counter=[2]
// [Fri Mar 11 11:51:15 2011] slot=[7] filename=[25.php] counter=[10]
// [Fri Mar 11 11:51:15 2011] slot=[8] filename=[2.php] counter=[7]
// [Fri Mar 11 11:51:15 2011] slot=[9] filename=[1.php] counter=[5]
// [Fri Mar 11 11:51:15 2011] slot=[10] filename=[3.php] counter=[2]
// [Fri Mar 11 11:51:15 2011] slot=[11] filename=[5.php] counter=[2]
//
// vlimit_ip_stat.list sample
// [Fri Mar 11 11:54:29 2011] slot=[0] ipaddress=[172.16.71.46] counter=[6]
// [Fri Mar 11 11:54:29 2011] slot=[0] ipaddress=[172.16.71.47] counter=[5]
// [Fri Mar 11 11:54:29 2011] slot=[0] ipaddress=[172.16.71.48] counter=[7]
// [Fri Mar 11 11:54:29 2011] slot=[0] ipaddress=[172.16.71.40] counter=[3]
// [Fri Mar 11 11:54:29 2011] slot=[0] ipaddress=[172.16.71.49] counter=[1]
// -------------------------------------------------------------------
*/
