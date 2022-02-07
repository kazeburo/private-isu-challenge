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

