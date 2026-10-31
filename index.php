
<?php
session_start();

// Enable MySQLi exceptions for database errors.
mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);

// Create a CSRF token for the form.
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$message = "";
$messageType = "";
$username = "";
$email = "";

try {
    // Connect to MySQL database.
    $conn = new mysqli("localhost", "root", "", "practical9");
    $conn->set_charset("utf8mb4");
} catch (mysqli_sql_exception $e) {
    die("Database connection failed. Check XAMPP and database settings.");
}

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $username = trim($_POST["username"] ?? "");
    $email = trim($_POST["email"] ?? "");
    $password = $_POST["password"] ?? "";
    $confirmPassword = $_POST["confirm_password"] ?? "";
    $csrfToken = $_POST["csrf_token"] ?? "";

    // 1. Verify CSRF token.
    if (!hash_equals($_SESSION['csrf_token'], $csrfToken)) {
        $message = "Invalid form request. Please refresh the page.";
        $messageType = "error";
    }

    // 2. Backend validation.
    elseif (
        $username === "" ||
        $email === "" ||
        $password === "" ||
        $confirmPassword === ""
    ) {
        $message = "All fields are required.";
        $messageType = "error";
    } elseif (!preg_match('/^[a-zA-Z0-9_]{3,30}$/', $username)) {
        $message = "Username must be 3-30 characters using letters, numbers, or underscores.";
        $messageType = "error";
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $message = "Please enter a valid email address.";
        $messageType = "error";
    } elseif (strlen($password) < 8) {
        $message = "Password must be at least 8 characters long.";
        $messageType = "error";
    } elseif ($password !== $confirmPassword) {
        $message = "Passwords do not match.";
        $messageType = "error";
    } else {
        // 3. Check for duplicate username.
        $checkUser = $conn->prepare(
            "SELECT id FROM users WHERE username = ?"
        );
        $checkUser->bind_param("s", $username);
        $checkUser->execute();
        $checkUser->store_result();

        $usernameExists = $checkUser->num_rows > 0;
        $checkUser->close();

        // 4. Check for duplicate email.
        $checkEmail = $conn->prepare(
            "SELECT id FROM users WHERE email = ?"
        );
        $checkEmail->bind_param("s", $email);
        $checkEmail->execute();
        $checkEmail->store_result();

        $emailExists = $checkEmail->num_rows > 0;
        $checkEmail->close();

        if ($usernameExists) {
            $message = "This username is already registered.";
            $messageType = "error";
        } elseif ($emailExists) {
            $message = "This email is already registered.";
            $messageType = "error";
        } else {
            // 5. Hash password before saving.
            $hashedPassword = password_hash(
                $password,
                PASSWORD_DEFAULT
            );

            try {
                // 6. Insert user using a prepared statement.
                $stmt = $conn->prepare(
                    "INSERT INTO users (username, email, password)
                     VALUES (?, ?, ?)"
                );
                $stmt->bind_param(
                    "sss",
                    $username,
                    $email,
                    $hashedPassword
                );
                $stmt->execute();
                $stmt->close();

                $message = "Registration successful! Your account has been created.";
                $messageType = "success";

                // Clear the form values after successful registration.
                $username = "";
                $email = "";

                // Generate a fresh token.
                $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
            } catch (mysqli_sql_exception $e) {
                // The database UNIQUE constraints are a second safeguard.
                if ($e->getCode() === 1062) {
                    $message = "That username or email is already registered.";
                } else {
                    $message = "Registration failed. Please try again.";
                }
                $messageType = "error";
            }
        }
    }
}

$conn->close();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secure User Registration</title>

    <style>
        * {
            box-sizing: border-box;
        }

        body {
            font-family: Arial, sans-serif;
            background: #f1f5f9;
            margin: 0;
            padding: 30px 15px;
        }

        .container {
            max-width: 430px;
            margin: 20px auto;
            background: white;
            padding: 28px;
            border-radius: 10px;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1);
        }

        h2 {
            text-align: center;
            color: #1e293b;
        }

        label {
            display: block;
            margin-top: 15px;
            margin-bottom: 6px;
            font-weight: bold;
        }

        input {
            width: 100%;
            padding: 11px;
            border: 1px solid #cbd5e1;
            border-radius: 5px;
        }

        input:focus {
            outline: 2px solid #93c5fd;
            border-color: #2563eb;
        }

        button {
            width: 100%;
            margin-top: 22px;
            padding: 12px;
            border: none;
            border-radius: 5px;
            background: #2563eb;
            color: white;
            font-size: 16px;
            cursor: pointer;
        }

        button:hover {
            background: #1d4ed8;
        }

        .message {
            padding: 12px;
            border-radius: 5px;
            margin-bottom: 15px;
            overflow-wrap: anywhere;
        }

        .success {
            color: #166534;
            background: #dcfce7;
        }

        .error {
            color: #991b1b;
            background: #fee2e2;
        }

        .hint {
            color: #64748b;
            font-size: 12px;
        }
    </style>
</head>

<body>
    <div class="container">
        <h2>Create Account</h2>

        <?php if ($message !== ""): ?>
            <div class="message <?= htmlspecialchars($messageType) ?>">
                <?= htmlspecialchars($message) ?>
            </div>
        <?php endif; ?>

        <form method="POST" action="" autocomplete="on">
            <input
                type="hidden"
                name="csrf_token"
                value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>"
            >

            <label for="username">Username</label>
            <input
                type="text"
                id="username"
                name="username"
                value="<?= htmlspecialchars($username) ?>"
                minlength="3"
                maxlength="30"
                pattern="[A-Za-z0-9_]{3,30}"
                title="Use 3-30 letters, numbers, or underscores."
                required
            >
            <div class="hint">3-30 letters, numbers, or underscores.</div>

            <label for="email">Email Address</label>
            <input
                type="email"
                id="email"
                name="email"
                value="<?= htmlspecialchars($email) ?>"
                maxlength="100"
                required
            >

            <label for="password">Password</label>
            <input
                type="password"
                id="password"
                name="password"
                minlength="8"
                autocomplete="new-password"
                required
            >
            <div class="hint">At least 8 characters.</div>

            <label for="confirm_password">Confirm Password</label>
            <input
                type="password"
                id="confirm_password"
                name="confirm_password"
                minlength="8"
                autocomplete="new-password"
                required
            >

            <button type="submit">Register</button>
        </form>
    </div>
</body>
</html>
