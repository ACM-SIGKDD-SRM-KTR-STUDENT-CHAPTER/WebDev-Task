# Web Development Task for ACM SIGKDD SRMIST Student Chapter

## Task 1: Backend System for E-commerce Inventory Management

**Objective**: Design a admin side backend system using Node.js with Express and MongoDB that handles the following features:

### Features:
1. **User Authentication & Authorization**:
   - Implement secure user registration and login using JWT or session-based authentication.

2. **Product Management Endpoints**:
   - **GET** `/products`:
     - Retrieve a list of products.
     - Filter by `category`, `price_range`, `sort_by` (e.g., price or popularity).
   - **POST** `/products`:
     - Add new products.
   - **PUT** `/product/:id`:
     - Update product details.
   - **DELETE** `/product/:id`:
     - Delete a product by its ID.

### Tech Stack:
- **Backend**: Node.js, Express.js
- **Database**: MongoDB
- **Authentication**: JWT (or sessions)
- **Deployment**: Optional (using services like Heroku or AWS)

### Folder Structure:
- Submission should be in the format `Backend/your_name`.
- Include all backend files in this folder.

### Important:
- **Do not** push any environment variables or sensitive information to the repository. Use a `.env` file for environment variables and add it to `.gitignore`.
- Ensure `node_modules/` is also added to `.gitignore` to avoid pushing the folder to the repository.

---

## Task 2: Frontend - Recreate Figma Design

**Objective**: Recreate the provided Figma design as a static website using React or Next.js.

### Requirements:
- Use **React** or **Next.js** for frontend development.
- No need to add any functionality like authentication or payments at this stage.
- Ensure the layout, styling, and responsiveness match the Figma design.
- Use any styling method (CSS modules, styled-components, or regular CSS).

### Figma Design:
- [Design Link](https://www.figma.com/design/ybVnNrnPCcTVwXa3sLOrGW/your-file?node-id=0-1&t=ZuDfoRoUsuHtPzB1-1)

### Folder Structure:
- Submission should be in the format `Frontend/your_name`.
- Include all frontend files in this folder.

### Important:
- **Do not** push `node_modules/` to the repository. Ensure it is listed in `.gitignore`.

---

## Submission Guidelines:
- Submit your work in this single GitHub repository.
- Folder structure should follow this format:
  ```
  Backend/your_name
  Frontend/your_name
  ```
- Ensure both backend and frontend have their own `.gitignore` files to exclude `node_modules/` and sensitive information.
- Add a `README` to explain how to set up and run both projects.

**Deadline**: 25th September 2024
