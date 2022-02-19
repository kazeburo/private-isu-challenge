# private-isu-try

## 環境

さくらのクラウド 東京第二ゾーン 2core/1GBサーバ

## 初期スコア

```
{"pass":true,"score":1857,"success":1994,"fail":11,"messages":["リクエストがタイムアウトしました (GET /)","リクエストがタイムアウトしました (GET /logout)","リクエストがタイムアウトしました (GET /posts)","リクエストがタイムアウトしました (POST /login)"]}
{"pass":true,"score":1914,"success":1992,"fail":8,"messages":["リクエストがタイムアウトしました (GET /)","リクエストがタイムアウトしました (GET /logout)","リク エストがタイムアウトしました (GET /posts)","リクエストがタイムアウトしました (POST /login)"]}
{"pass":true,"score":2053,"success":2113,"fail":7,"messages":["リクエストがタイムアウトしました (GET /)","リクエストがタイムアウトしました (GET /logout)","リク エストがタイムアウトしました (GET /posts)","リクエストがタイムアウトしました (POST /login)"]}
```

## post_id_idx 追加

```
mysql> ALTER TABLE `comments` ADD INDEX `post_id_idx` (`post_id`);
Query OK, 0 rows affected (0.63 sec)
Records: 0  Duplicates: 0  Warnings: 0
```

score

```
{"pass":true,"score":11531,"success":9791,"fail":0,"messages":[]}
{"pass":true,"score":11715,"success":9938,"fail":0,"messages":[]}
{"pass":true,"score":11207,"success":9529,"fail":0,"messages":[]}
```

## my.conf

追加

```
innodb_flush_method=O_DIRECT
innodb_flush_log_at_trx_commit = 2
disable-log-bin = 1
```

score

```
{"pass":true,"score":11087,"success":9361,"fail":0,"messages":[]}
{"pass":true,"score":11533,"success":9674,"fail":0,"messages":[]}
{"pass":true,"score":11221,"success":9507,"fail":0,"messages":[]}
```

## post_id_idx 張り替え

```
mysql> ALTER TABLE `comments` DROP INDEX `post_id_idx`, ADD INDEX `post_id_idx` (`post_id`, `created_at` DESC);
Query OK, 0 rows affected (0.42 sec)
Records: 0  Duplicates: 0  Warnings: 0
```

score

```
{"pass":true,"score":11379,"success":9617,"fail":0,"messages":[]}
{"pass":true,"score":11106,"success":9315,"fail":0,"messages":[]}
{"pass":true,"score":11135,"success":9352,"fail":0,"messages":[]}
```

## order by狙いのkey

```
mysql> alter table posts add index posts_order_idx (created_at DESC);
Query OK, 0 rows affected (0.05 sec)
Records: 0  Duplicates: 0  Warnings: 0
```

score


```
{"pass":true,"score":11338,"success":9562,"fail":0,"messages":[]}
{"pass":true,"score":11295,"success":9499,"fail":0,"messages":[]}
{"pass":true,"score":11330,"success":9481,"fail":0,"messages":[]}
```

## user_idx追加

```
mysql> ALTER TABLE `comments` ADD INDEX `idx_user_id` (`user_id`);
Query OK, 0 rows affected (0.34 sec)
Records: 0  Duplicates: 0  Warnings: 0
```

score

```
{"pass":true,"score":12208,"success":10351,"fail":0,"messages":[]}
{"pass":true,"score":11716,"success":9811,"fail":0,"messages":[]}
{"pass":true,"score":11597,"success":9701,"fail":0,"messages":[]}
```

## JOIN

score

```
{"pass":true,"score":10287,"success":8772,"fail":4,"messages":["response code should be 200, got 502 (GET /)","response code should be 200, got 502 (POST /login)"]}
{"pass":true,"score":10491,"success":8938,"fail":0,"messages":[]}
{"pass":true,"score":10371,"success":8774,"fail":0,"messages":[]}
```

## postsPerPage


score

```
{"pass":true,"score":18957,"success":14918,"fail":0,"messages":[]}
{"pass":true,"score":19263,"success":15201,"fail":0,"messages":[]}
{"pass":true,"score":19088,"success":14943,"fail":0,"messages":[]}
```

## reduce N+1 in makePosts

```
{"pass":true,"score":20707,"success":16220,"fail":0,"messages":[]}
{"pass":true,"score":20570,"success":16099,"fail":0,"messages":[]}
{"pass":true,"score":21075,"success":16575,"fail":0,"messages":[]}
```

## post_user_idx

```
mysql> ALTER TABLE posts ADD INDEX posts_user_idx (user_id, created_at DESC);
Query OK, 0 rows affected (0.20 sec)
Records: 0  Duplicates: 0  Warnings: 0
```

score

```
{"pass":true,"score":11824,"success":10273,"fail":0,"messages":[]}
{"pass":true,"score":11923,"success":10318,"fail":0,"messages":[]}
{"pass":true,"score":12334,"success":10726,"fail":0,"messages":[]}
```

## Straight join

score

```
{"pass":true,"score":23417,"success":18320,"fail":0,"messages":[]}
{"pass":true,"score":22620,"success":17615,"fail":0,"messages":[]}
{"pass":true,"score":22510,"success":17545,"fail":0,"messages":[]}
```

## tune mysql driver

score

```
{"pass":true,"score":26054,"success":20131,"fail":0,"messages":[]}
{"pass":true,"score":24823,"success":19254,"fail":0,"messages":[]}
{"pass":true,"score":24870,"success":19306,"fail":0,"messages":[]}
```

## nginx静的ファイル

```
  location /css/ {
    root /home/isucon/private_isu/webapp/public/;
    expires 1d;
  }

  location /js/ {
    root /home/isucon/private_isu/webapp/public/;
    expires 1d;
  }
```

score

```
{"pass":true,"score":24783,"success":19185,"fail":0,"messages":[]}
{"pass":true,"score":25601,"success":19929,"fail":0,"messages":[]}
{"pass":true,"score":24114,"success":18659,"fail":0,"messages":[]}
```

## nginx keepalive

```
upstream app {
  server localhost:8080;
  keepalive 100;
  keepalive_requests 10000;
}

server {
  location / {
    proxy_set_header Host $host;
    proxy_http_version 1.1;
    proxy_set_header Connection "";
    proxy_pass http://app;
    #proxy_pass http://localhost:8080;
  }
}
```

score

```
{"pass":true,"score":25181,"success":19458,"fail":0,"messages":[]}
{"pass":true,"score":26567,"success":20568,"fail":0,"messages":[]}
{"pass":true,"score":25108,"success":19349,"fail":0,"messages":[]}
```


## 外部コマンド

score

```
{"pass":true,"score":25820,"success":19993,"fail":0,"messages":[]}
{"pass":true,"score":26260,"success":20327,"fail":0,"messages":[]}
{"pass":true,"score":26218,"success":20275,"fail":0,"messages":[]}
```

## imageをnginxで配信

nginx

```
  location /image/ {
    root /home/isucon/private_isu/webapp/public/;
    try_files $uri $uri/ @app;
    expires 1d;
  }

  location @app {
    proxy_set_header Host $host;
    proxy_http_version 1.1;
    proxy_set_header Connection "";
    proxy_pass http://app;
  }
```

score

```
{"pass":true,"score":102228,"success":96402,"fail":0,"messages":[]}
{"pass":true,"score":99284,"success":93499,"fail":0,"messages":[]}
{"pass":true,"score":103508,"success":97773,"fail":0,"messages":[]}
```

## no store imgdata to DB

```
mysql> CREATE TABLE `images` (
    ->   `id` int NOT NULL,
    ->   `mime` varchar(64) NOT NULL,
    ->   `imgdata` mediumblob NOT NULL,
    ->   PRIMARY KEY (`id`)
    -> ) ENGINE=InnoDB;
Query OK, 0 rows affected (0.01 sec)

mysql> INSERT INTO `images` (`id`,`mime`,`imgdata`) SELECT `id`,`mime`,`imgdata` FROM `posts`;
Query OK, 10157 rows affected (1 min 36.56 sec)
Records: 10157  Duplicates: 0  Warnings: 0

mysql> UPDATE `posts` SET `imgdata` = '';
Query OK, 10157 rows affected (24.60 sec)
Rows matched: 10157  Changed: 10157  Warnings: 0

mysql> ALTER TABLE `posts` Engine=InnoDB;
Query OK, 0 rows affected (2.40 sec)
Records: 0  Duplicates: 0  Warnings: 0
```

score

```
{"pass":true,"score":85899,"success":82084,"fail":0,"messages":[]}
{"pass":true,"score":89106,"success":85166,"fail":0,"messages":[]}
{"pass":true,"score":94567,"success":90438,"fail":0,"messages":[]}
```

## STRAIGHT_JOIN => FORCE INDEX

一部straigt_joinでは解決できず

```
{"pass":true,"score":121775,"success":115740,"fail":0,"messages":[]}
{"pass":true,"score":123021,"success":117054,"fail":0,"messages":[]}
{"pass":true,"score":125152,"success":118955,"fail":0,"messages":[]}
```

## countコラム追加。コメントカウントのN+1解消

```
mysql> ALTER TABLE posts ADD comment_count INT NOT NULL DEFAULT 0;
Query OK, 0 rows affected (0.18 sec)
Records: 0  Duplicates: 0  Warnings: 0

mysql> UPDATE posts SET posts.comment_count = (SELECT COUNT(id) FROM comments WHERE comments.post_id = posts.id);
Query OK, 10045 rows affected (0.24 sec)
Rows matched: 10211  Changed: 10045  Warnings: 0

mysql> DELIMITER $$
mysql> CREATE
    -> TRIGGER insert_comments
    -> AFTER UPDATE
    -> ON comments
    -> FOR EACH ROW
    -> BEGIN
    -> UPDATE post SET comment_count = comment_count + 1 WHERE id = NEW.post_id;
    -> END $$
Query OK, 0 rows affected (0.00 sec)

mysql> DELIMITER ;
```
score

```
{"pass":true,"score":136117,"success":128770,"fail":0,"messages":[]}
{"pass":true,"score":133864,"success":126304,"fail":0,"messages":[]}
{"pass":true,"score":129888,"success":122383,"fail":0,"messages":[]}
```

## window関数でN+1解消

```
{"pass":true,"score":181792,"success":169672,"fail":0,"messages":[]}
{"pass":true,"score":185707,"success":174122,"fail":0,"messages":[]}
{"pass":true,"score":169360,"success":157604,"fail":0,"messages":[]}
```

## cache template instance

```
{"pass":true,"score":183153,"success":170872,"fail":0,"messages":[]}
{"pass":true,"score":184688,"success":173026,"fail":0,"messages":[]}
{"pass":true,"score":183120,"success":171368,"fail":0,"messages":[]}
```

## cache recent comment

```
{"pass":true,"score":185196,"success":172629,"fail":0,"messages":[]}
{"pass":true,"score":199426,"success":185801,"fail":0,"messages":[]}
{"pass":true,"score":192533,"success":178806,"fail":0,"messages":[]}
```

## 1Gbps

間のNICが100Mbpsだということに気づいた。1Gbpsに変更

```
{"pass":true,"score":386446,"success":371974,"fail":0,"messages":[]}
{"pass":true,"score":386678,"success":372111,"fail":0,"messages":[]}
{"pass":true,"score":387717,"success":373109,"fail":0,"messages":[]}
```

## cache index

using singleflight

```
{"pass":true,"score":462445,"success":445206,"fail":0,"messages":[]}
{"pass":true,"score":421277,"success":405654,"fail":0,"messages":[]}
{"pass":true,"score":464326,"success":447450,"fail":0,"messages":[]}
```

## no memcached cookie

```
{"pass":true,"score":481488,"success":461570,"fail":0,"messages":[]}
{"pass":true,"score":481375,"success":461535,"fail":0,"messages":[]}
{"pass":true,"score":484997,"success":464795,"fail":0,"messages":[]}
```

## tune nginx.conf


etag off
access_log off

```
keepalive_requests 10000;

upstream app {
  server localhost:8080;
  keepalive 100;
  keepalive_requests 10000;
}

server {
  listen 80;

  client_max_body_size 10m;
  root /home/isucon/private_isu/webapp/public/;
  access_log off;

  location /css/ {
    root /home/isucon/private_isu/webapp/public/;
    expires 1d;
    etag off;
  }

  location /js/ {
    root /home/isucon/private_isu/webapp/public/;
    expires 1d;
    etag off;
  }

  location /image/ {
    root /home/isucon/private_isu/webapp/public/;
    try_files $uri $uri/ @app;
    expires 1d;
    etag off;
  }

  location /favicon.ico {
    root /home/isucon/private_isu/webapp/public/;
    expires 1d;
    etag off;
  }
```

```
{"pass":true,"score":513284,"success":494301,"fail":0,"messages":[]}
{"pass":true,"score":509519,"success":490768,"fail":0,"messages":[]}
{"pass":true,"score":468520,"success":451011,"fail":0,"messages":[]}
```

## Cache User and tune getAccountName

```
{"pass":true,"score":524554,"success":502282,"fail":0,"messages":[]}
{"pass":true,"score":521505,"success":499573,"fail":0,"messages":[]}
{"pass":true,"score":522132,"success":500001,"fail":0,"messages":[]}
```

nginxの負荷が高い

```
top - 10:12:59 up 10:41,  1 user,  load average: 0.75, 0.16, 0.05
Tasks:  91 total,   2 running,  89 sleeping,   0 stopped,   0 zombie
%Cpu(s): 58.9 us, 17.4 sy,  0.0 ni,  9.0 id,  2.7 wa,  0.0 hi, 10.6 si,  1.5 st
MiB Mem :    981.1 total,    112.7 free,    336.9 used,    531.5 buff/cache
MiB Swap:   4096.0 total,   3813.2 free,    282.8 used.    497.7 avail Mem 

    PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND
   2551 isucon    20   0 1446692  61116   5984 S  93.3   6.1   6:24.91 app
    470 mysql     20   0 1752684 166576   7428 S  31.7  16.6  17:06.28 mysqld
   2219 www-data  20   0   56484   4664   2116 S  28.3   0.5   3:48.12 nginx
   2218 www-data  20   0   56788   4672   2116 S  20.3   0.5   2:52.02 nginx
```

## Cache Posts

```
{"pass":true,"score":549803,"success":526221,"fail":0,"messages":[]}
{"pass":true,"score":544678,"success":521165,"fail":0,"messages":[]}
{"pass":true,"score":543109,"success":519612,"fail":0,"messages":[]}
```

## getLogin template cache

忘れてた

```
{"pass":true,"score":556188,"success":532511,"fail":0,"messages":[]}
{"pass":true,"score":532122,"success":509214,"fail":0,"messages":[]}
{"pass":true,"score":548705,"success":525309,"fail":0,"messages":[]}
```

## Bye template

templateをつかわない

```
{"pass":true,"score":629775,"success":590641,"fail":0,"messages":[]}
{"pass":true,"score":619105,"success":580828,"fail":0,"messages":[]}
{"pass":true,"score":627211,"success":588384,"fail":0,"messages":[]}
```

appのCPUがかなり削減

```
Tasks:  91 total,   3 running,  88 sleeping,   0 stopped,   0 zombie
%Cpu(s): 46.2 us, 20.8 sy,  0.0 ni, 14.0 id,  4.2 wa,  0.0 hi, 14.6 si,  0.2 st
MiB Mem :    981.1 total,     69.7 free,    302.2 used,    609.1 buff/cache
MiB Swap:   4096.0 total,   3760.5 free,    335.5 used.    529.1 avail Mem

    PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND
  35167 isucon    20   0 1305024  65896   8308 S  59.5   6.6   0:32.61 app
    470 mysql     20   0 1750636 140692   9580 S  33.6  14.0  35:20.34 mysqld
  33787 www-data  20   0   56856   4676   2016 R  32.2   0.5   5:33.81 nginx
  33786 www-data  20   0   56796   4616   2016 R  29.9   0.5   4:23.76 nginx   
```

## Cache getIndex

singleflightでcacheつくる。必要な時だけcacheをupdate

```
{"pass":true,"score":650841,"success":608564,"fail":0,"messages":[]}
{"pass":true,"score":624772,"success":584408,"fail":0,"messages":[]}
{"pass":true,"score":637138,"success":595814,"fail":0,"messages":[]}
```

## use fiber !

fiber/fasthttpを使う

```
{"pass":true,"score":754500,"success":702446,"fail":0,"messages":[]}
{"pass":true,"score":759413,"success":707031,"fail":0,"messages":[]}
{"pass":true,"score":761191,"success":709146,"fail":0,"messages":[]}
```

CPUもさらに低く

```
Tasks:  99 total,   3 running,  96 sleeping,   0 stopped,   0 zombie
%Cpu(s): 37.7 us, 23.1 sy,  0.0 ni, 18.6 id,  4.0 wa,  0.0 hi, 16.2 si,  0.3 st
MiB Mem :    981.1 total,     67.5 free,    309.5 used,    604.0 buff/cache
MiB Swap:   4096.0 total,   3729.6 free,    366.4 used.    522.4 avail Mem

    PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND
  37655 isucon    20   0 1376088  65472   9220 S  49.0   6.5   1:22.77 /home/isucon/private_isu/webapp/golang/app -bind 0.0.0.0:80
  36053 mysql     20   0 1765660 120184   3192 S  37.0  12.0   9:36.78 /usr/sbin/mysqld
  36873 www-data  20   0   56628   2636   1516 R  29.7   0.3   2:27.17 nginx: worker process
  36872 www-data  20   0   56628   2644   1528 R  27.3   0.3   2:18.39 nginx: worker process 
```

## インスタンスが変わったのでもう一度

```
{"pass":true,"score":859301,"success":801879,"fail":0,"messages":[]}
{"pass":true,"score":851529,"success":794599,"fail":0,"messages":[]}
{"pass":true,"score":845544,"success":789678,"fail":0,"messages":[]}
```

```
Tasks:  93 total,   4 running,  89 sleeping,   0 stopped,   0 zombie
%Cpu(s): 34.6 us, 24.5 sy,  0.0 ni, 17.9 id,  4.2 wa,  0.0 hi, 18.9 si,  0.0 st
MiB Mem :    981.1 total,     66.6 free,    432.4 used,    482.1 buff/cache
MiB Swap:   4096.0 total,   3926.2 free,    169.8 used.    401.5 avail Mem

    PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND
    1079 isucon    20   0 1234704  61756   7924 R  46.5   6.1   0:21.57 /home/isucon/private_isu/webapp/golang/app -bind 0.0.0.0:80
    859 mysql     20   0 1731664 303320   9864 S  33.9  30.2   1:38.95 /usr/sbin/mysqld
    818 www-data  20   0   56364   4036   1860 R  33.2   0.4   1:18.98 nginx: worker process
    817 www-data  20   0   56364   3992   1824 R  30.2   0.4   1:24.36 nginx: worker process
```

## NO nginx

nginxなくしても速くなる

```
$ sudo systemctl disable nginx
$ sudo systemctl stop nginx
```

```
{"pass":true,"score":986681,"success":916302,"fail":0,"messages":[]}
{"pass":true,"score":978396,"success":907240,"fail":0,"messages":[]}
{"pass":true,"score":968167,"success":900282,"fail":0,"messages":[]}
```

メモリは気になる

```
top - 16:25:14 up 35 min,  1 user,  load average: 1.78, 1.20, 1.05
Tasks:  86 total,   2 running,  84 sleeping,   0 stopped,   0 zombie
%Cpu(s): 42.1 us, 18.6 sy,  0.0 ni, 17.4 id,  4.9 wa,  0.0 hi, 16.9 si,  0.0 st
MiB Mem :    981.1 total,     74.2 free,    620.1 used,    286.7 buff/cache
MiB Swap:   4096.0 total,   3776.7 free,    319.2 used.    214.7 avail Mem

    PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND
   1367 isucon    20   0 1871876 392696   5208 R 107.6  39.1   4:43.72 app
    859 mysql     20   0 1734000 160404   5132 S  38.2  16.0   4:11.73 mysqld
```
