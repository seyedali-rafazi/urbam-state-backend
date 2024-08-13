# Saghfinoo backend App

## Under Development

This is the backend application for a house rental platform, built using Node.js, Express.js, and MongoDB. The app provides a RESTful API for handling user authentication, car management, rental management, and other functionalities.

## Features

- **User Authentication**: Signup, login, and JWT-based token management
- **House Management**: CRUD operations for houses, models, makes, etc.
- **Rental Management**: Creating reservations, tracking rental status, etc.
- **Payment Integration**: Coming soon
- **Admin Dashboard**: Managing users, cars, and rentals

## Technologies Used

- **Node.js**
- **Express.js**
- **MongoDB** (with Mongoose ORM)
- **JSON Web Tokens (JWT)** for authentication
- **Bcrypt** for password hashing
- **Axios** for HTTP requests
- **Joi** for input validation
- **Kavenegar** for SMS messaging
- **Moment.js** for date/time handling

## Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/seyedali-rafazi/saghfinoo-backend.git
    ```

2. Navigate to the project directory:
    ```bash
    cd saghfinoo-backend
    ```

3. Install dependencies:
    ```bash
    npm install
    ```

4. Create a `.env` file in the root directory and add the necessary environment variables:
    ```
    PORT=your_port_number
    MONGO_URI=your_mongodb_connection_string
    JWT_SECRET=your_jwt_secret
    KAVENEGAR_API_KEY=your_kavenegar_api_key
    ```

5. Start the development server:
    ```bash
    npm run dev
    ```

## Contact

For any questions or inquiries, please contact the project maintainers at [seyedalirafazi80@gmail.com].
