<?php
use \Psr\Http\Message\ServerRequestInterface as Request;
use \Psr\Http\Message\ResponseInterface as Response;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

require '../src/vendor/autoload.php';
$app = new \Slim\App;

$app->post('/user/register', function (Request $request, Response $response, array $args)
{
    $data=json_decode($request->getBody());
    $uname=$data->username ;
    $pass=$data->password ;
    $servername="localhost" ;
    $password="";
    $username="root";
    
    $dbname="library";

    try{
        $conn = new PDO("mysql:host=$servername; dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $sql = "INSERT INTO users (username, password) VALUES('". $uname."','".hash('sha256',$pass)."')";
        $conn->exec($sql);
        $response->getBody()->write(json_encode(array("status"=>"success","data"=>null)));

    }catch(PDOException$e){
        $response->getBody()->write(json_encode(array("status"=>"fail","data"=>array("title"=>$e->getMessage()))));
    }
    $conn=null;
    return $response;
}); 

$app->post('/user/auth', function (Request $request, Response $response, array $args)
{   error_reporting(E_ALL);
    $data=json_decode($request->getBody());
    $uname=$data->username ;
    $pass=$data->password ;
    $servername="localhost" ;
    $password="";
    $username="root";
    $dbname="library";

    try{
        $conn = new PDO("mysql:host=$servername; dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $sql = "SELECT * FROM users WHERE username = '".$uname."' AND password='".hash('SHA256',$pass)."'";
        $stmt=$conn->prepare($sql);
        $stmt->execute();
        $stmt->setFetchMode(PDO::FETCH_ASSOC);
        $data=$stmt->fetchAll();

        if(count($data)==1){
            $key='chesterthegreat';
            $iat=time();
            $payload=[
                'iss'=> 'http://library.org',
                'aud'=>'http://library.com',
                'iat'=> $iat, //creation time
                'exp'=> $iat + 3600,
                'data'=>array(
                    "userid"=>$data[0]['userid'])
                ];
                
                $jwt=JWT::encode($payload, $key, 'HS256');
                $response->getBody()->write(
               json_encode(array("status"=>"success","token"=>$jwt,"data"=>null)));    
        }
        else{
        $response->getBody()->write(
            json_encode(array("status"=>"fail","data"=>array("title"=>"authentication failed")))
        );
    }
    }catch(PDOException $e){
        $response->getBody()->write(json_encode(array("status"=>"fail","data"=>array("title"=>$e->getMessage()))));
    }
    $conn=null;
    return $response;
}); 

// UPDATE user info
$app->put('/user/update', function (Request $request, Response $response, array $args) {
    $data = json_decode($request->getBody());
    $newUsername = $data->new_username;
    $newPassword = $data->new_password;
    $token = $data->token;

    $servername = "localhost";
    $dbusername = "root";
    $dbpassword = "";
    $dbname = "library";
    $key = 'chesterthegreat';

    try {
        // Decode JWT token to get the userid
        $decoded = JWT::decode($token, new Key($key, 'HS256'));
        $userid = $decoded->data->userid;

        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $dbusername, $dbpassword);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $sql = "UPDATE users SET username = :username, password = :password WHERE userid = :userid";
        $stmt = $conn->prepare($sql);
        $stmt->execute([
            'username' => $newUsername,
            'password' => hash('sha256', $newPassword),
            'userid' => $userid
        ]);

        if ($stmt->rowCount() > 0) {
            $response->getBody()->write(json_encode(array("status" => "success", "data" => "User updated successfully")));
        } else {
            $response->getBody()->write(json_encode(array("status" => "fail", "data" => "No changes made")));
        }
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    } catch (Exception $e) {
        $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => "Invalid Token, Please Login Again"))));
    }

    $conn = null;
    return $response;
});

$app->delete('/user/delete', function (Request $request, Response $response, array $args) {
    $data = json_decode($request->getBody());
    $token = $data->token;

    $servername = "localhost";
    $dbusername = "root";
    $dbpassword = "";
    $dbname = "library";
    $key = 'chesterthegreat';

    try {
        $decoded = JWT::decode($token, new Key($key, 'HS256'));
        $userid = $decoded->data->userid;

        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $dbusername, $dbpassword);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $sql = "DELETE FROM users WHERE userid = :userid";
        $stmt = $conn->prepare($sql);
        $stmt->execute(['userid' => $userid]);

        if ($stmt->rowCount() > 0) {
            $response->getBody()->write(json_encode(array("status" => "success", "data" => "User deleted successfully")));
        } else {
            $response->getBody()->write(json_encode(array("status" => "fail", "data" => "No user found to delete")));
        }
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    } catch (Exception $e) {
        $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => "Invalid Token, Please Login Again"))));
    }

    $conn = null;
    return $response;
});

$app->post('/display/users', function (Request $request, Response $response, array $args) {
    $data = json_decode($request->getBody());
    $jwt = $data->token;
    $userid = $data->userid;
    $servername = "localhost";
    $dbusername = "root";
    $dbpassword = "";
    $dbname = "cabalo_lib";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $dbusername, $dbpassword);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Check for token record
        $sql = "SELECT * FROM used_tokens WHERE userid = :userid";
        $stmt = $conn->prepare($sql);
        $stmt->execute(['userid' => $userid]);
        $userdata = $stmt->fetch(PDO::FETCH_ASSOC);

        // Log the fetched data for debugging
        error_log("Fetched User Data: " . print_r($userdata, true)); // Log the userdata

        if (!$userdata) {
            $response->getBody()->write(json_encode(array("status" => "fail", "data" => "No matching record for the provided token.")));
            return $response;
        } elseif ($userdata['token'] !== $jwt) {
            // Log the expected vs actual token for debugging
            error_log("Expected Token: " . $userdata['token']);
            error_log("Provided Token: " . $jwt);
            $response->getBody()->write(json_encode(array("status" => "fail", "data" => "Invalid token.")));
            return $response;
        } else {
            // Fetch and display all users
            $sql = "SELECT userid, username FROM users";
            $stmt = $conn->prepare($sql);
            $stmt->execute();
            $users = $stmt->fetchAll(PDO::FETCH_ASSOC);

            if ($users) {
                $response->getBody()->write(json_encode(array("status" => "success", "data" => $users)));
            } else {
                $response->getBody()->write(json_encode(array("status" => "fail", "data" => "No users found.")));
            }
        }
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    } catch (Exception $e) {
        $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => "An error occurred."))));
    }

    $conn = null;
    return $response;
});


$app->post('/add/books', function (Request $request, Response $response, array $args) {
    $data = json_decode($request->getBody());

    // Ensure the required fields are present
    if (!isset($data->loc, $data->author, $data->title, $data->token)) {
        return $response->withStatus(400)->write(json_encode([
            "status" => "fail", 
            "message" => "Missing required fields."
        ]));
    }

    $loc = $data->loc;
    $author = $data->author;
    $title = $data->title;
    $jwt = $data->token;

    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";
    $key = 'chesterthegreat'; // Use your actual secret key here

    try {
        // Decode the JWT
        $decoded = JWT::decode($jwt, new Key($key, 'HS256'));

        // Connect to the database
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Check if the token exists and is unused
        $sql = "SELECT * FROM tokens WHERE token = :token AND expires_at > NOW() AND used = 0";
        $stmt = $conn->prepare($sql);
        $stmt->execute(['token' => $jwt]);
        $tokenData = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$tokenData) {
            return $response->withStatus(403)->write(json_encode([
                "status" => "fail", 
                "message" => "Invalid or expired token."
            ]));
        }

        // Check if the token is for the "add_book" activity
        if ($decoded->activity !== 'add_book') {
            return $response->withStatus(403)->write(json_encode([
                "status" => "fail", 
                "message" => "Invalid token activity."
            ]));
        }

        // Proceed with adding the book logic...

        // Check if the author exists, insert if not
        $sql = "SELECT authorid FROM authors WHERE name = :author";
        $stmt = $conn->prepare($sql);
        $stmt->execute(['author' => $author]);
        $existingAuthor = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$existingAuthor) {
            // Insert new author if not found
            $sql = "INSERT INTO authors (name) VALUES (:author)";
            $stmt = $conn->prepare($sql);
            $stmt->execute(['author' => $author]);
            $authorid = $conn->lastInsertId();
        } else {
            $authorid = $existingAuthor['authorid'];
        }

       

        // Check if the book already exists
        $sql = "SELECT COUNT(*) FROM books WHERE title = :title AND authorid = :authorid";
        $stmt = $conn->prepare($sql);
        $stmt->execute(['title' => $title, 'authorid' => $authorid]);
        $existingBookCount = $stmt->fetchColumn();

        if ($existingBookCount > 0) {
            // Book already exists
            return $response->withStatus(409)->write(json_encode([
                "status" => "fail", 
                "data" => ["title" => "Book with the same title and author already exists"]
            ]));
        } else {
            // Insert new book
            $sql = "INSERT INTO books (title, authorid,) VALUES (:title, :authorid,)";
            $stmt = $conn->prepare($sql);
            $stmt->execute(['title' => $title, 'authorid' => $authorid]);
            $bookid = $conn->lastInsertId();

            // Generate a new token for future requests
            $iat = time();
            $newPayload = [
                'iss' => 'http://library.org',
                'aud' => 'http://library.com',
                'iat' => $iat,
                'exp' => $iat + 3600, // Token expires in 1 hour
                'activity' => 'add_book',
                'single_use' => true, // New token is single-use
                'used' => false, // New token is not used
                'data' => [
                    'userid' => $decoded->data->userid // Pass the user ID from the original token
                ]
            ];

            $newjwt = JWT::encode($newPayload, $key, 'HS256');

            // Update the token in the database (mark old token as used and replace it with the new token)
            $sql = "UPDATE used_tokens SET token = :newtoken, used = 1, updated_at = NOW() WHERE id = :id";
            $stmt = $conn->prepare($sql);
            $stmt->execute(['newtoken' => $newjwt, 'id' => $tokenData['id']]);

            // Prepare response for successful addition with new token
            $response->getBody()->write(json_encode([
                "status" => "success", 
                "token" => $newjwt,
                "data" => ["bookid" => $bookid]
            ]));
            return $response->withStatus(201); // Return 201 for resource created
        }
    } catch (PDOException $e) {
        return $response->withStatus(500)->write(json_encode([
            "status" => "fail", 
            "data" => ["title" => $e->getMessage()]
        ]));
    } catch (Exception $e) {
        return $response->withStatus(401)->write(json_encode([
            "status" => "fail", 
            "message" => "Invalid or expired token."
        ]));
    } finally {
        // Close the database connection
        $conn = null;
    }
});


$app->post('/add/author', function (Request $request, Response $response, array $args)
{
    $data = json_decode($request->getBody());
    $authorname = $data->authorname;
    $servername = "localhost";
    $password = "";
    $username = "root";
    $dbname = "library";

    $key = 'chesterthegreat';
    $jwt = $data->token;
    
    try {
        // Decode and verify JWT token
        jwt::decode($jwt, new Key($key, 'HS256'));

        try {
            $conn = new PDO("mysql:host=$servername; dbname=$dbname", $username, $password);
            $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

            // Check if the author already exists in the database
            $sql = "SELECT COUNT(*) FROM authors WHERE name = :authorname";
            $stmt = $conn->prepare($sql);
            $stmt->execute(['authorname' => $authorname]);
            $authorExists = $stmt->fetchColumn();

            if ($authorExists > 0) {
                // Author already exists, return a "duplicate" response
                $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => "Author already exists"))));
            } else {
                // Insert the new author since it doesn't exist yet
                $sql = "INSERT INTO authors (name) VALUES (:authorname)";
                $stmt = $conn->prepare($sql);
                $stmt->execute(['authorname' => $authorname]);

                $response->getBody()->write(json_encode(array("status" => "success", "data" => null)));
            }

        } catch (PDOException $e) {
            // Handle SQL errors
            $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
        }
    } catch (Exception $e) {
        // Handle token verification failure
        $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => "Token Expired, Please Relogin"))));
    }
    
    $conn = null;
    return $response;
});



$app->get('/read/allbooks', function (Request $request, Response $response, array $args) {
    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        
        $sql = "SELECT * FROM books";
        $stmt = $conn->query($sql);
        $books = $stmt->fetchAll(PDO::FETCH_ASSOC);

        $response->getBody()->write(json_encode(array("status"=>"success", "data"=>$books)));
    } catch(PDOException $e) {
        $response->getBody()->write(json_encode(array("status"=>"fail", "data"=>array("title"=>$e->getMessage()))));
    }

    $conn = null;
    return $response;
});
$app->get('/read/books/{bookid}', function (Request $request, Response $response, array $args) {
    $bookid = $args['bookid'];
    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        
        $sql = "SELECT * FROM books WHERE bookid = :bookid";
        $stmt = $conn->prepare($sql);
        $stmt->execute(['bookid' => $bookid]);
        $book = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($book) {
            $response->getBody()->write(json_encode(array("status"=>"success", "data"=>$book)));
        } else {
            $response->getBody()->write(json_encode(array("status"=>"fail", "data"=>array("title"=>"Book not found"))));
        }
    } catch(PDOException $e) {
        $response->getBody()->write(json_encode(array("status"=>"fail", "data"=>array("title"=>$e->getMessage()))));
    }

    $conn = null;
    return $response;
});
$app->get('/read/allauthors', function (Request $request, Response $response, array $args) {
    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        
        $sql = "SELECT * FROM authors";
        $stmt = $conn->query($sql);
        $authors = $stmt->fetchAll(PDO::FETCH_ASSOC);

        $response->getBody()->write(json_encode(array("status"=>"success", "data"=>$authors)));
    } catch(PDOException $e) {
        $response->getBody()->write(json_encode(array("status"=>"fail", "data"=>array("title"=>$e->getMessage()))));
    }

    $conn = null;
    return $response;
});

$app->get('/read/authors/{authorid}', function (Request $request, Response $response, array $args) {
    $authorid = $args['authorid'];
    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $sql = "SELECT name as author_name, title as book_title, 
                FROM books_author ba
                JOIN authors a ON a.authorid = ba.authorid
                JOIN books b ON b.bookid = ba.bookid
                WHERE a.authorid = :authorid";
                
        $stmt = $conn->prepare($sql);
        $stmt->execute(['authorid' => $authorid]);
        $books = $stmt->fetchAll(PDO::FETCH_ASSOC);

        if ($books) {
            $response->getBody()->write(json_encode(array("status" => "success", "data" => $books)));
        } else {
            $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("message" => "No books found for this author"))));
        }
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("message" => $e->getMessage()))));
    }

    $conn = null;
    return $response;
});



$app->put('/update/books/{bookid}', function (Request $request, Response $response, array $args) {
    $bookid = $args['bookid'];
    $data = json_decode($request->getBody());
    $title = $data->title;
    $author = $data->author;
    
    
    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";
    
    $key = 'chesterthegreat';
    $jwt = $data->token;
    
    try {
        // Verify JWT token
        jwt::decode($jwt, new Key($key, 'HS256'));

        try {
            $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
            $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

            // Check if author exists, otherwise insert new author
            $sql = "SELECT authorid FROM authors WHERE name = :author";
            $stmt = $conn->prepare($sql);
            $stmt->execute(['author' => $author]);
            $existingAuthor = $stmt->fetch(PDO::FETCH_ASSOC);

            if (!$existingAuthor) {
                $sql = "INSERT INTO authors (name) VALUES (:author)";
                $stmt = $conn->prepare($sql);
                $stmt->execute(['author' => $author]);
                $authorid = $conn->lastInsertId();  // New author inserted
            } else {
                $authorid = $existingAuthor['authorid'];  // Existing author found
            }

            

           
            // Update book details with valid authorid and locid
            $sql = "UPDATE books SET title = :title, authorid = :authorid WHERE bookid = :bookid";
            $stmt = $conn->prepare($sql);
            $stmt->execute([
                'title' => $title,
                'authorid' => $authorid,
    
                'bookid' => $bookid
            ]);

            $response->getBody()->write(json_encode(array("status" => "success", "data" => null)));
        } catch (PDOException $e) {
            // Handle SQL errors
            $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
        }
    } catch (Exception $e) {
        // Handle token verification failure
        $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => "Token Expired, Please Relogin"))));
    }

    $conn = null;
    return $response;
});

$app->put('/update/authors/{authorid}', function (Request $request, Response $response, array $args) {
    $authorid = $args['authorid'];
    $data = json_decode($request->getBody());
    $name = $data->name;
    
    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";
    
    $key = 'chesterthegreat';
    $jwt = $data->token;
    
    try {
        // Verify JWT token
        jwt::decode($jwt, new Key($key, 'HS256'));


    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        
        $sql = "UPDATE authors SET name = :name WHERE authorid = :authorid";
        $stmt = $conn->prepare($sql);
        $stmt->execute(['name' => $name, 'authorid' => $authorid]);

        $response->getBody()->write(json_encode(array("status"=>"success", "data"=>null)));
    } catch(PDOException $e) {
        $response->getBody()->write(json_encode(array("status"=>"fail", "data"=>array("title"=>$e->getMessage()))));
    }
} catch (Exception $e) {
    // Handle token verification failure
    $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => "Token Expired, Please Relogin"))));
}

    $conn = null;
    return $response;
});



$app->delete('/delete/books/{bookid}', function (Request $request, Response $response, array $args) {
    $bookid = $args['bookid'];
    
    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";
    $key ='chesterthegreat';
    $data=json_decode($request->getBody());
    $jwt=$data->token;
    try{
    jwt::decode($jwt, new Key($key, 'HS256'));
    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        
        $sql = "DELETE FROM books WHERE bookid = :bookid";
        $stmt = $conn->prepare($sql);
        $stmt->execute(['bookid' => $bookid]);

        $response->getBody()->write(json_encode(array("status"=>"success", "data"=>null)));
    } catch(PDOException $e) {
        $response->getBody()->write(json_encode(array("status"=>"fail", "data"=>array("title"=>$e->getMessage()))));
    }
}
catch(Exception $e){
    $response->getBody()->write(json_encode(array("status"=>"fail","data"=>array("title"=>"Token Expired, Please Relogin"))));
}

    $conn = null;
    return $response;
});
$app->delete('/delete/authors/{authorid}', function (Request $request, Response $response, array $args) {
    $authorid = $args['authorid'];
    
    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";
    $key ='chesterthegreat';
    $data=json_decode($request->getBody());
    $jwt=$data->token;
    try{
    jwt::decode($jwt, new Key($key, 'HS256'));
    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        
        $sql = "DELETE FROM authors WHERE authorid = :authorid";
        $stmt = $conn->prepare($sql);
        $stmt->execute(['authorid' => $authorid]);
        $response->getBody()->write(json_encode(array("status"=>"success", "data"=>null)));
    } catch(PDOException $e) {
        $response->getBody()->write(json_encode(array("status"=>"fail", "data"=>array("title"=>$e->getMessage()))));
    }
}
catch(Exception $e){
    $response->getBody()->write(json_encode(array("status"=>"fail","data"=>array("title"=>"Token Expired, Please Relogin"))));
}
    $conn = null;
    return $response;
});



$app->run();
