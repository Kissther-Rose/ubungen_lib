<?php
use \Psr\Http\Message\ServerRequestInterface as Request;
use \Psr\Http\Message\ResponseInterface as Response;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

require '../src/vendor/autoload.php';
$app = new \Slim\App([
    'settings' => [
        'displayErrorDetails' => true,  
    ]
]);

//REGISTRATION

$app->post('/user/register', function (Request $request, Response $response, array $args) {
    $data = json_decode($request->getBody());
    $uname = $data->username;
    $pass = $data->password;
    $servername = "localhost";
    $password = "";
    $username = "root";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername; dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Check if the username already exists
        $sql = "SELECT * FROM users WHERE username = :username";
        $stmt = $conn->prepare($sql);
        $stmt->execute([':username' => $uname]);
        $existingUser = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($existingUser) {
            // If username exists, return an error response
            $response->getBody()->write(json_encode(array(
                "status" => "fail",
                "data" => array("Result:" => "Username already exists")
            )));
            return $response;
        }

        // Proceed to insert new user
        $sql = "INSERT INTO users (username, password) VALUES (:username, :password)";
        $stmt = $conn->prepare($sql);
        $stmt->execute([
            ':username' => $uname,
            ':password' => hash('sha256', $pass)
        ]);

        $response->getBody()->write(json_encode(array("status" => "success", "data" => null)));

    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    }
    $conn = null;
    return $response;
});


//AUTHENTICATION

$app->post('/user/auth', function (Request $request, Response $response, array $args) {
    $data = json_decode($request->getBody());
    $unameOrId = $data->useridOrUsername; // Can be either username or userid
    $pass = $data->password;
    $servername = "localhost";
    $password = "";
    $username = "root";
    $dbname = "library";

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Check if input is username or userid
        $sql = "SELECT * FROM users WHERE (username = :unameOrId OR userid = :unameOrId) AND password = :password";
        $stmt = $conn->prepare($sql);
        $stmt->execute([
            ':unameOrId' => $unameOrId,
            ':password' => hash('SHA256', $pass)
        ]);
        
        $stmt->setFetchMode(PDO::FETCH_ASSOC);
        $data = $stmt->fetchAll();

        if (count($data) == 1) {
            $userid = $data[0]['userid'];
            $key = 'kisstherrose';
            $iat = time();
            $payload = [
                'iss' => 'http://library.org',
                'aud' => 'http://library.com',
                'iat' => $iat,
                'exp' => $iat + 1800,
                'data' => array("userid" => $userid)
            ];
            
            $jwt = JWT::encode($payload, $key, 'HS256');
            
            $sql = "SELECT * FROM used_tokens WHERE userid = :userid";
            $stmt = $conn->prepare($sql);
            $stmt->execute([':userid' => $userid]);

            if ($stmt->rowCount() > 0) {
                $sql = "UPDATE used_tokens SET token = :token WHERE userid = :userid";
                $stmt = $conn->prepare($sql);
                $stmt->execute([
                    ':token' => $jwt,
                    ':userid' => $userid
                ]);
            } else {
                $sql = "INSERT INTO used_tokens (token, userid) VALUES (:token, :userid)";
                $stmt = $conn->prepare($sql);
                $stmt->execute([
                    ':token' => $jwt,
                    ':userid' => $userid
                ]);
            }

            $response->getBody()->write(
                json_encode(array("status" => "success", "token" => $jwt, "data" => null))
            );
        } else {
            $response->getBody()->write(
                json_encode(array("status" => "fail", "data" => array("title" => "Authentication failed")))
            );
        }
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    }

    $conn = null;
    return $response;
});

// Register logAudit function in the Slim container
$container = $app->getContainer();

$container['logAudit'] = function ($container) {
    return function ($userid, $action, $message) {
        $servername = "localhost";
        $username = "root";
        $password = "";
        $dbname = "library";

        try {
            $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
            $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

            // Insert audit log into the database
            $sql = "INSERT INTO audit_logs (userid, action, message, timestamp) VALUES (:userid, :action, :message, NOW())";
            $stmt = $conn->prepare($sql);
            $stmt->execute([
                'userid' => $userid,
                'action' => $action,
                'message' => $message
            ]);
        } catch (PDOException $e) {
            error_log("Audit log error: " . $e->getMessage());
        }
    };
};


$app->post('/lock-account/{userid}', function (Request $request, Response $response, array $args) {
    $userid = $args['userid'];
    $data = json_decode($request->getBody());
    $jwt = $data->token;

    try {
        // Database connection
        $servername = "localhost";
        $username = "root";
        $password = "";
        $dbname = "library";

        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Validate token
        $sql = "SELECT * FROM used_tokens WHERE userid = :userid";
        $stmt = $conn->prepare($sql);
        $stmt->execute(['userid' => $userid]);
        $userdata = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$userdata) {
            $response->getBody()->write(json_encode(array("status" => "no token", "data" => null)));
        } elseif ($userdata['token'] != $jwt) {
            $response->getBody()->write(json_encode(array("status" => "invalid token", "data" => null)));
        } else {
            // Lock the account
            $sql = "UPDATE users SET account_locked = 1 WHERE userid = :userid";
            $stmt = $conn->prepare($sql);
            $stmt->execute(['userid' => $userid]);

            // Log the action using the logAudit method from the container
            $this->get('logAudit')($userid, 'lock_account', 'Account locked');

            $response->getBody()->write(json_encode(array("status" => "success", "data" => "Account locked successfully")));
        }
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(array("status" => "fail", "data" => $e->getMessage())));
    }

    return $response;
});

$app->post('/unlock-account/{userid}', function (Request $request, Response $response, array $args) {
    $userid = $args['userid'];
    $data = json_decode($request->getBody());
    $jwt = $data->token;

    try {
        // Connect to the database
        $servername = "localhost";
        $username = "root";
        $password = "";
        $dbname = "library";  // Your database name

        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Validate token
        $sql = "SELECT * FROM used_tokens WHERE userid = :userid";
        $stmt = $conn->prepare($sql);
        $stmt->execute(['userid' => $userid]);
        $userdata = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$userdata) {
            $response->getBody()->write(json_encode(array("status" => "no token", "data" => null)));
        } elseif ($userdata['token'] != $jwt) {
            $response->getBody()->write(json_encode(array("status" => "invalid token", "data" => null)));
        } else {
            // Unlock the account
            $sql = "UPDATE users SET account_locked = 0 WHERE userid = :userid";
            $stmt = $conn->prepare($sql);
            $stmt->execute(['userid' => $userid]);

            // Log the action using the logAudit function from the container
            $this->get('logAudit')($userid, 'unlock_account', 'Account unlocked');

            $response->getBody()->write(json_encode(array("status" => "success", "data" => "Account unlocked successfully")));
        }
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(array("status" => "fail", "data" => $e->getMessage())));
    }

    return $response;
});


//USER UPDATE

$app->put('/user/update', function (Request $request, Response $response, array $args) {
    $data = json_decode($request->getBody());
    $newUsername = $data->new_username;
    $newPassword = $data->new_password;
    $jwt = $data->token;
    $userid = $data->userid;
    $servername = "localhost";
    $dbusername = "root";
    $dbpassword = "";
    $dbname = "library";
    $key = 'kisstherrose';

    try {
        
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $dbusername, $dbpassword);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
       
        $sql = "SELECT * FROM used_tokens WHERE userid = :userid";
        $stmt = $conn->prepare($sql);
        $stmt->execute(['userid' => $userid]);
        $userdata = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$userdata){
            $response->getBody()->write(json_encode(array("status" => "no token", "data" => null)));
        } else
        if ($userdata ['token'] != $jwt){
            $response->getBody()->write(json_encode(array("status" => "invalid token", "data" => null)));
        }else{
        
        $sql = "UPDATE users SET username = :username, password = :password WHERE userid = :userid";
        $stmt = $conn->prepare($sql);
        $stmt->execute([
            'username' => $newUsername,
            'password' => hash('sha256', $newPassword),
            'userid' => $userid
        ]);

        if ($stmt->rowCount() > 0) {
            $key='kisstherrose';
                $iat=time();
                $payload=[
                    'iss'=> 'http://library.org',
                    'aud'=>'http://library.com',
                    'iat'=> $iat, 
                    'exp'=> $iat + 1800,
                    'data'=>array(
                        "userid"=>$userid)
                ];

                $jwt=JWT::encode($payload, $key, 'HS256');
                $sql = "UPDATE used_tokens SET token = :token  WHERE userid = :userid";
                $stmt = $conn->prepare($sql);
                $stmt->execute([
                    'token' => $jwt,
                    'userid'=> $userid   
            ]);
            $response->getBody()->write(json_encode(array("status" => "success", "data" => "User updated successfully","newToken" =>$jwt)));
        } else {
            $response->getBody()->write(json_encode(array("status" => "fail", "data" => "No changes made")));
        }}
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    } catch (Exception $e) {
        $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => "Invalid Token, Please Login Again"))));
    }

    $conn = null;
    return $response;
});

//USER DELETE

$app->delete('/user/delete', function (Request $request, Response $response, array $args) {
    $data = json_decode($request->getBody());
    $jwt = $data->token;
    $userid = $data->userid;
    $servername = "localhost";
    $dbusername = "root";
    $dbpassword = "";
    $dbname = "library";
    $key = 'kisstherrose';

    try {
       
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $dbusername, $dbpassword);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $sql = "SELECT * FROM used_tokens WHERE userid = :userid";
        $stmt = $conn->prepare($sql);
        $stmt->execute(['userid' => $userid]);
        $userdata = $stmt->fetch(PDO::FETCH_ASSOC);
        

        if (!$userdata){
            $response->getBody()->write(json_encode(array("status" => "no token", "data" => null)));
        } else
        if ($userdata ['token'] != $jwt){
            $response->getBody()->write(json_encode(array("status" => "invalid token", "data" => null)));
        }else{

        $sql = "DELETE FROM users WHERE userid = :userid";
        $stmt = $conn->prepare($sql);
        $stmt->execute(['userid' => $userid]);

        if ($stmt->rowCount() > 0) {
            $key='kisstherrose';
            $iat=time();
            $payload=[
                'iss'=> 'http://library.org',
                'aud'=>'http://library.com',
                'iat'=> $iat, 
                'exp'=> $iat + 1800,
                'data'=>array(
                    "userid"=>$userid)
            ];

            $jwt=JWT::encode($payload, $key, 'HS256');
            $sql = "UPDATE used_tokens SET token = :token  WHERE userid = :userid";
            $stmt = $conn->prepare($sql);
            $stmt->execute([
                'token' => $jwt,
                'userid'=> $userid   
        ]);
            $response->getBody()->write(json_encode(array("status" => "success", "data" => "User deleted successfully","newToken" =>$jwt)));
        } else {
            $response->getBody()->write(json_encode(array("status" => "fail", "data" => "No user found to delete")));
        }}
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    } catch (Exception $e) {
        $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => "Invalid Token, Please Login Again"))));
    }

    $conn = null;
    return $response;
});

//FIND USER

$app->post('/find/user', function (Request $request, Response $response, array $args) {
    $data = json_decode($request->getBody());
    $jwt = $data->token;  
    $userid = $data->userid;
    $servername = "localhost";
    $dbusername = "root";
    $dbpassword = "";
    $dbname = "library";

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
            // Find the user
            $sql = "SELECT userid, username FROM users WHERE userid = :userid OR username = :userid";
            $stmt = $conn->prepare($sql);
            $stmt->execute(['userid' => $userid]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($user) {
                $response->getBody()->write(json_encode(array("status" => "success", "data" => "Match found for the user: " . $user['username'])));
            } else {
                $response->getBody()->write(json_encode(array("status" => "fail", "data" => "No matching record for the user.")));
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



// ADD BOOKS

$app->post('/add/books', function (Request $request, Response $response, array $args) {
    $data = json_decode($request->getBody());
    $author = $data->author;
    $title = $data->title;
    $userid = $data->userid;
    $jwt = $data->token;

    // Database connection details
    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    try {
        // Establish database connection
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Validate user token
        $sql = "SELECT * FROM used_tokens WHERE userid = :userid";
        $stmt = $conn->prepare($sql);
        $stmt->execute(['userid' => $userid]);
        $userdata = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$userdata) {
            return $response->withJson(array("status" => "no token", "data" => null));
        } elseif ($userdata['token'] != $jwt) {
            return $response->withJson(array("status" => "invalid token", "data" => null));
        }

        // Check if the author exists
        $sql = "SELECT authorid FROM authors WHERE name = :author";
        $stmt = $conn->prepare($sql);
        $stmt->execute(['author' => $author]);
        $existingAuthor = $stmt->fetch(PDO::FETCH_ASSOC);

        // Insert the new author if not found
        if (!$existingAuthor) {
            $sql = "INSERT INTO authors (name) VALUES (:author)";
            $stmt = $conn->prepare($sql);
            $stmt->execute(['author' => $author]);
            $authorid = $conn->lastInsertId();
        } else {
            $authorid = $existingAuthor['authorid'];
        }

        // Check if the book already exists for the author
        $sql = "SELECT COUNT(*) FROM books WHERE title = :title AND authorid = :authorid";
        $stmt = $conn->prepare($sql);
        $stmt->execute(['title' => $title, 'authorid' => $authorid]);
        $existingBookCount = $stmt->fetchColumn();

        if ($existingBookCount > 0) {
            return $response->withJson(array("status" => "fail", "data" => "Book with the same title and author already exists."));
        } else {
            // Insert new book if no duplicate found
            $sql = "INSERT INTO books (title, authorid) VALUES (:title, :authorid)";
            $stmt = $conn->prepare($sql);
            $stmt->execute(['title' => $title, 'authorid' => $authorid]);

            // Optionally, update the token for the user
            $iat = time();
            $payload = [
                'iss' => 'http://library.org',
                'aud' => 'http://library.com',
                'iat' => $iat,
                'exp' => $iat + 1800,
                'data' => array(
                    "userid" => $userid
                )
            ];
            $newJwt = JWT::encode($payload, 'kisstherrose', 'HS256');
            $sql = "UPDATE used_tokens SET token = :token WHERE userid = :userid";
            $stmt = $conn->prepare($sql);
            $stmt->execute(['token' => $newJwt, 'userid' => $userid]);

            return $response->withJson(array("status" => "success", "data" => null, "newToken" => $newJwt));
        }
    } catch (PDOException $e) {
        return $response->withJson(array("status" => "fail", "data" => array("title" => $e->getMessage())));
    } catch (Exception $e) {
        return $response->withJson(array("status" => "fail", "data" => array("title" => "Token Expired, Please Relogin")));
    } finally {
        // Close the connection
        $conn = null;
    }
});


//ADD AUTHOR

$app->post('/add/author', function (Request $request, Response $response, array $args)
{
    $data = json_decode($request->getBody());
    $authorname = $data->authorname;
    $userid = $data->userid;  // Changed back to userid
    $servername = "localhost";
    $password = "";
    $username = "root";
    $dbname = "library";

    $key = 'kisstherrose';
    $jwt = $data->token;
    
    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Check if the token is valid for the user
        $sql = "SELECT * FROM used_tokens WHERE userid = :userid";  // Changed back to userid
        $stmt = $conn->prepare($sql);
        $stmt->execute(['userid' => $userid]);
        $userdata = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$userdata) {
            $response->getBody()->write(json_encode(array("status" => "no token", "data" => null)));
            return $response;
        } elseif ($userdata['token'] != $jwt) {
            $response->getBody()->write(json_encode(array("status" => "invalid token", "data" => null)));
            return $response;
        }

        // Check for duplicate authorname
        $sql = "SELECT COUNT(*) FROM authors WHERE name = :authorname";
        $stmt = $conn->prepare($sql);
        $stmt->execute(['authorname' => $authorname]);
        $authorExists = $stmt->fetchColumn();

        if ($authorExists > 0) {
            // If the author already exists, return a failure response
            $response->getBody()->write(json_encode(array("status" => "fail", "data" => "Author already exists")));  // Removed title from response
            return $response;
        }

        // If the author does not exist, insert the new author
        $sql = "INSERT INTO authors (name) VALUES (:authorname)";
        $stmt = $conn->prepare($sql);
        $stmt->execute(['authorname' => $authorname]);

        // Generate new JWT token
        $iat = time();
        $payload = [
            'iss' => 'http://library.org',
            'aud' => 'http://library.com',
            'iat' => $iat, 
            'exp' => $iat + 1800,
            'data' => array("userid" => $userid)  // Changed back to userid
        ];

        $jwt = JWT::encode($payload, $key, 'HS256');
        $sql = "UPDATE used_tokens SET token = :token WHERE userid = :userid";  // Changed back to userid
        $stmt = $conn->prepare($sql);
        $stmt->execute(['token' => $jwt, 'userid' => $userid]);

        // Return success response
        $response->getBody()->write(json_encode(array("status" => "success", "data" => null, "newToken" => $jwt)));
    } catch (Exception $e) {
        // Return error response for token expiration or other issues
        $response->getBody()->write(json_encode(array("status" => "fail", "data" => "Token Expired or Invalid")));
    } finally {
        $conn = null;
    }

    return $response;
});


//READ ALL BOOKS

$app->get('/find/allbooks', function (Request $request, Response $response, array $args) {
    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    $data = json_decode($request->getBody());
    $userid = $data->userid;
    $key = 'kisstherrose';
    $jwt = $data->token;

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $sql = "SELECT * FROM used_tokens WHERE userid = :userid";
        $stmt = $conn->prepare($sql);
        $stmt->execute(['userid' => $userid]);
        $userdata = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$userdata) {
            $response->getBody()->write(json_encode(array("status" => "no token", "data" => null)));
        } elseif ($userdata['token'] != $jwt) {
            $response->getBody()->write(json_encode(array("status" => "invalid token", "data" => null)));
        } else {
            $sql = "SELECT * FROM books";
            $stmt = $conn->query($sql);
            $books = $stmt->fetchAll(PDO::FETCH_ASSOC);

            $iat = time();
            $payload = [
                'iss' => 'http://library.org',
                'aud' => 'http://library.com',
                'iat' => $iat,
                'exp' => $iat + 1800,
                'data' => array("userid" => $userid)
            ];

            $jwt = JWT::encode($payload, $key, 'HS256');
            $sql = "UPDATE used_tokens SET token = :token WHERE userid = :userid";
            $stmt = $conn->prepare($sql);
            $stmt->execute(['token' => $jwt, 'userid' => $userid]);

            $response->getBody()->write(json_encode(array("status" => "success", "data" => $books, "newToken" => $jwt)));
        }
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
    }

    $conn = null;
    return $response;
});


//FIND A BOOK

$app->get('/find/books/{bookid}', function (Request $request, Response $response, array $args) {
    $bookid = $args['bookid'];
    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    $data = json_decode($request->getBody());
    $userid = $data->userid;
    $key = 'kisstherrose';
    $jwt = $data->token;

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $sql = "SELECT * FROM used_tokens WHERE userid = :userid";
        $stmt = $conn->prepare($sql);
        $stmt->execute(['userid' => $userid]);
        $userdata = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$userdata) {
            $response->getBody()->write(json_encode(array("status" => "no token", "data" => null)));
        } elseif ($userdata['token'] != $jwt) {
            $response->getBody()->write(json_encode(array("status" => "invalid token", "data" => null)));
        } else {
            $sql = "SELECT * FROM books WHERE bookid = :bookid";
            $stmt = $conn->prepare($sql);
            $stmt->execute(['bookid' => $bookid]);
            $book = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($book) {
                $iat = time();
                $payload = [
                    'iss' => 'http://library.org',
                    'aud' => 'http://library.com',
                    'iat' => $iat,
                    'exp' => $iat + 1800,
                    'data' => array("userid" => $userid)
                ];

                $jwt = JWT::encode($payload, $key, 'HS256');
                $sql = "UPDATE used_tokens SET token = :token WHERE userid = :userid";
                $stmt = $conn->prepare($sql);
                $stmt->execute(['token' => $jwt, 'userid' => $userid]);

                $response->getBody()->write(json_encode(array("status" => "success", "data" => $book, "newToken" => $jwt)));
            } else {
                $response->getBody()->write(json_encode(array("status" => "fail", "data" => "Book not found")));
            }
        }
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(array("status" => "fail", "data" => $e->getMessage())));
    }

    $conn = null;
    return $response;
});


//FIND ALL AUTHORS

$app->get('/find/allauthors', function (Request $request, Response $response, array $args) {
    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    $data = json_decode($request->getBody());
    $userid = $data->userid;
    $key = 'kisstherrose';
    $jwt = $data->token;

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Check for token validity
        $sql = "SELECT * FROM used_tokens WHERE userid = :userid";
        $stmt = $conn->prepare($sql);
        $stmt->execute(['userid' => $userid]);
        $userdata = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$userdata) {
            $response->getBody()->write(json_encode(array("status" => "no token", "data" => null)));
        } elseif ($userdata['token'] != $jwt) {
            $response->getBody()->write(json_encode(array("status" => "invalid token", "data" => null)));
        } else {
            // Fetch all authors
            $sql = "SELECT * FROM authors";
            $stmt = $conn->query($sql);
            $authors = $stmt->fetchAll(PDO::FETCH_ASSOC);

            // Generate new token
            $iat = time();
            $payload = [
                'iss' => 'http://library.org',
                'aud' => 'http://library.com',
                'iat' => $iat,
                'exp' => $iat + 1800,
                'data' => array("userid" => $userid)
            ];

            $jwt = JWT::encode($payload, $key, 'HS256');
            $sql = "UPDATE used_tokens SET token = :token WHERE userid = :userid";
            $stmt = $conn->prepare($sql);
            $stmt->execute(['token' => $jwt, 'userid' => $userid]);

            // Return success response
            $response->getBody()->write(json_encode(array("status" => "success", "data" => $authors, "newToken" => $jwt)));
        }
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("message" => $e->getMessage()))));
    }

    $conn = null;
    return $response;
});


//FIND AUTHOR

$app->get('/find/authors/{authorid}', function (Request $request, Response $response, array $args) {
    $authorid = $args['authorid'];
    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";

    $data = json_decode($request->getBody());
    $userid = $data->userid;
    $key = 'kisstherrose';
    $jwt = $data->token;

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $sql = "SELECT * FROM used_tokens WHERE userid = :userid";
        $stmt = $conn->prepare($sql);
        $stmt->execute(['userid' => $userid]);
        $userdata = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$userdata) {
            $response->getBody()->write(json_encode(array("status" => "no token", "data" => null)));
        } elseif ($userdata['token'] != $jwt) {
            $response->getBody()->write(json_encode(array("status" => "invalid token", "data" => null)));
        } else {
            
            $sql = "SELECT a.name as author_name, b.title as book_title
                    FROM books_author ba
                    JOIN authors a ON a.authorid = ba.authorid
                    JOIN books b ON b.bookid = ba.bookid
                    WHERE a.authorid = :authorid";

            $stmt = $conn->prepare($sql);
            $stmt->execute(['authorid' => $authorid]);
            $author = $stmt->fetchAll(PDO::FETCH_ASSOC);

            if ($author) {
                $iat = time();
                $payload = [
                    'iss' => 'http://library.org',
                    'aud' => 'http://library.com',
                    'iat' => $iat,
                    'exp' => $iat + 1800,
                    'data' => array(
                        "userid" => $userid
                    )
                ];

                $jwt = JWT::encode($payload, $key, 'HS256');
                $sql = "UPDATE used_tokens SET token = :token WHERE userid = :userid";
                $stmt = $conn->prepare($sql);
                $stmt->execute([
                    'token' => $jwt,
                    'userid' => $userid   
                ]);

                $response->getBody()->write(json_encode(array("status" => "success", "data" => $author, "newToken" => $jwt)));
            } else {
                $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("message" => "Author found, but no books are linked to this author."))));
            }
        }
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("message" => $e->getMessage()))));
    }

    $conn = null;
    return $response;
});



// UPDATE BOOK
$app->put('/update/books/{bookid}', function (Request $request, Response $response, array $args) {
    $bookid = $args['bookid'];
    $data = json_decode($request->getBody());
    $title = $data->title;
    $author = $data->author;

    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";
    $userid = $data->userid;
    $key = 'kisstherrose';
    $jwt = $data->token;

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $sql = "SELECT * FROM used_tokens WHERE userid = :userid";
        $stmt = $conn->prepare($sql);
        $stmt->execute(['userid' => $userid]);
        $userdata = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$userdata) {
            $response->getBody()->write(json_encode(array("status" => "no token", "data" => null)));
        } elseif ($userdata['token'] != $jwt) {
            $response->getBody()->write(json_encode(array("status" => "invalid token", "data" => null)));
        } else {
            try {
                // Find or insert author
                $sql = "SELECT authorid FROM authors WHERE name = :author";
                $stmt = $conn->prepare($sql);
                $stmt->execute(['author' => $author]);
                $existingAuthor = $stmt->fetch(PDO::FETCH_ASSOC);

                if (!$existingAuthor) {
                    $sql = "INSERT INTO authors (name) VALUES (:author)";
                    $stmt = $conn->prepare($sql);
                    $stmt->execute(['author' => $author]);
                    $authorid = $conn->lastInsertId();  
                } else {
                    $authorid = $existingAuthor['authorid'];  
                }

                // Update book with new title and author
                $sql = "UPDATE books SET title = :title, authorid = :authorid WHERE bookid = :bookid";
                $stmt = $conn->prepare($sql);
                $stmt->execute([
                    'title' => $title,
                    'authorid' => $authorid,
                    'bookid' => $bookid
                ]);

                // Generate new token and update
                $iat = time();
                $payload = [
                    'iss' => 'http://library.org',
                    'aud' => 'http://library.com',
                    'iat' => $iat,
                    'exp' => $iat + 1800,
                    'data' => array("userid" => $userid)
                ];

                $jwt = JWT::encode($payload, $key, 'HS256');
                $sql = "UPDATE used_tokens SET token = :token WHERE userid = :userid";
                $stmt = $conn->prepare($sql);
                $stmt->execute([
                    'token' => $jwt,
                    'userid' => $userid   
                ]);

                $response->getBody()->write(json_encode(array("status" => "success", "data" => null, "newToken" => $jwt)));
            } catch (PDOException $e) {
                $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
            }
        }
    } catch (Exception $e) {
        $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => "Token Expired, Please Relogin"))));
    }

    $conn = null;
    return $response;
});

// UPDATE AUTHOR
$app->put('/update/authors/{authorid}', function (Request $request, Response $response, array $args) {
    $authorid = $args['authorid'];
    $data = json_decode($request->getBody());
    $name = $data->name;

    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";
    $userid = $data->userid;
    $key = 'kisstherrose';
    $jwt = $data->token;

    try {
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $sql = "SELECT * FROM used_tokens WHERE userid = :userid";
        $stmt = $conn->prepare($sql);
        $stmt->execute(['userid' => $userid]);
        $userdata = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$userdata) {
            $response->getBody()->write(json_encode(array("status" => "no token", "data" => null)));
        } elseif ($userdata['token'] != $jwt) {
            $response->getBody()->write(json_encode(array("status" => "invalid token", "data" => null)));
        } else {
            try {
                $sql = "UPDATE authors SET name = :name WHERE authorid = :authorid";
                $stmt = $conn->prepare($sql);
                $stmt->execute(['name' => $name, 'authorid' => $authorid]);

                $iat = time();
                $payload = [
                    'iss' => 'http://library.org',
                    'aud' => 'http://library.com',
                    'iat' => $iat, 
                    'exp' => $iat + 1800,
                    'data' => array("userid" => $userid)
                ];

                $jwt = JWT::encode($payload, $key, 'HS256');
                $sql = "UPDATE used_tokens SET token = :token WHERE userid = :userid";
                $stmt = $conn->prepare($sql);
                $stmt->execute([
                    'token' => $jwt,
                    'userid' => $userid   
                ]);

                $response->getBody()->write(json_encode(array("status" => "success", "data" => null, "newToken" => $jwt)));
            } catch (PDOException $e) {
                $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
            }
        }
    } catch (Exception $e) {
        $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => "Token Expired, Please Relogin"))));
    }

    $conn = null;
    return $response;
});

//DELETE BOOK

$app->delete('/delete/books/{bookid}', function (Request $request, Response $response, array $args) {
    $bookid = $args['bookid'];
    
    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";
    $key ='kisstherrose';
    $data=json_decode($request->getBody());
    $jwt=$data->token;
    $userid = $data->userid;
    try{
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $sql = "SELECT * FROM used_tokens WHERE userid = :userid";
        $stmt = $conn->prepare($sql);
            $stmt->execute(['userid' => $userid]);
        $userdata = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!$userdata){
            $response->getBody()->write(json_encode(array("status" => "no token", "data" => null)));
        }
        if ($userdata ['token'] != $jwt){
            $response->getBody()->write(json_encode(array("status" => "invalid token", "data" => null)));
        }else{
        
    try {
       
        $sql = "DELETE FROM books WHERE bookid = :bookid";
        $stmt = $conn->prepare($sql);
        $stmt->execute(['bookid' => $bookid]);

        $iat=time();
        $payload=[
            'iss'=> 'http://library.org',
            'aud'=>'http://library.com',
            'iat'=> $iat, 
            'exp'=> $iat + 1800,
            'data'=>array(
                "userid"=>$userid)
        ];

        $jwt=JWT::encode($payload, $key, 'HS256');
        $sql = "UPDATE used_tokens SET token = :token  WHERE userid = :userid";
        $stmt = $conn->prepare($sql);
        $stmt->execute([
            'token' => $jwt,
            'userid'=> $userid   
        ]);
        $response->getBody()->write(json_encode(array("status"=>"success", "data"=>null,"newToken" =>$jwt)));
    } catch(PDOException $e) {
        $response->getBody()->write(json_encode(array("status"=>"fail", "data"=>array("title"=>$e->getMessage()))));
    }}
}
catch(Exception $e){
    $response->getBody()->write(json_encode(array("status"=>"fail","data"=>array("title"=>"Token Expired, Please Relogin"))));
}

    $conn = null;
    return $response;
});

//DELETE AUTHOR

$app->delete('/delete/authors/{authorid}', function (Request $request, Response $response, array $args) {
    
    $authorid = $args['authorid'];
   
    $servername = "localhost";
    $username = "root";
    $password = "";
    $dbname = "library";
    $key ='kisstherrose';
    $data=json_decode($request->getBody());
    $userid = $data->userid;
    $jwt=$data->token;
    try{
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $sql = "SELECT * FROM used_tokens WHERE userid = :userid";
        $stmt = $conn->prepare($sql);
            $stmt->execute(['userid' => $userid]);
        $userdata = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!$userdata){
            $response->getBody()->write(json_encode(array("status" => "no token", "data" => null)));
        }
        if ($userdata ['token'] != $jwt){
            $response->getBody()->write(json_encode(array("status" => "invalid token", "data" => null)));
        }else{
    try {
       
        $sql = "DELETE FROM authors WHERE authorid = :authorid";
        $stmt = $conn->prepare($sql);
        $stmt->execute(['authorid' => $authorid]);

        $iat=time();
        $payload=[
            'iss'=> 'http://library.org',
            'aud'=>'http://library.com',
            'iat'=> $iat, 
            'exp'=> $iat + 1800,
            'data'=>array(
                "userid"=>$userid)
        ];

        $jwt=JWT::encode($payload, $key, 'HS256');
        $sql = "UPDATE used_tokens SET token = :token  WHERE userid = :userid";
        $stmt = $conn->prepare($sql);
        $stmt->execute([
            'token' => $jwt,
            'userid'=> $userid   
        ]);
        $response->getBody()->write(json_encode(array("status"=>"success", "data"=>null, "newToken" =>$jwt)));
    } catch(PDOException $e) {
        $response->getBody()->write(json_encode(array("status"=>"fail", "data"=>array("title"=>$e->getMessage()))));
    }}
}
catch(Exception $e){
    $response->getBody()->write(json_encode(array("status"=>"fail","data"=>array("title"=>"Token Expired, Please Relogin"))));
}
    $conn = null;
    return $response;
});


$app->run();

//go to https://github.com/firebase/php-jwt
//C:\xampp\htdocs\security\src>composer require firebase/php-jwt on cmd
