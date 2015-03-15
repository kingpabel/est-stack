<?php
// Define routes
$app->get('/', 'requireLogin', function () use ($app) {
    $user = App::getUser()->toArray();
    $app->log->info("Slim-Skeleton '/' route");
    $app->render('home.twig', array('user' => $user));
});

$app->get('/login', function () use ($app) {
    $app->log->info("Slim-Skeleton '/' route");

    $app->render('login.twig');
});

$app->post(
    '/login',
    function () use ($app) {
        $emailAddress = strtolower(filter_var($app->request()->post('email'), FILTER_SANITIZE_STRING));
        $password = filter_var($app->request()->post('password'), FILTER_SANITIZE_STRING);
        if ($user = User::where('email', $emailAddress)->first()) {

            if (password_verify($password, $user->password)) {
                $_SESSION['user'] = $user->uuid;
                $app->redirect('/');
            } else {
                $app->flash('error', 'Invalid email address and/or password');
                $app->redirect('/login');
            }
        } else {
            $app->flash('error', 'Invalid email address and/or password');
            $app->redirect('/login');
        }
    }
);
$app->get('/signup', function () use ($app) {
    if (App::userLoggedIn()) {
        $app->flash('error', 'You are already logged in');
        $app->redirect('/');
    }

    $app->log->info("Slim-Skeleton '/' route");

    $app->render('signup.twig');
});

$app->post(
    '/signup',
    function () use ($app) {
        $emailAddress = strtolower(filter_var($app->request()->post('email'), FILTER_SANITIZE_STRING));
        $password = filter_var($app->request()->post('password'), FILTER_SANITIZE_STRING);
        $firstName = filter_var($app->request()->post('firstName'), FILTER_SANITIZE_STRING);
        $lastName = filter_var($app->request()->post('lastName'), FILTER_SANITIZE_STRING);

        $user = new User();
        $user->first_name = $firstName;
        $user->last_name = $lastName;
        $user->email = $emailAddress;
        $user-> password = password_hash($password, PASSWORD_BCRYPT);
        $user->uuid = UUID::v4();
        if($user->save()){
            $app->flash('info', 'Signup successful. You may login now!');
            $app->redirect('/login');
        }else{
            $app->flash('error', 'Something went wrong!');
            $app->redirect('/signup');
        }
    }
);

$app->get(
    '/logout',
    function () use ($app) {
        unset($_SESSION['user']);
        $app->redirect('/login');
    }
);