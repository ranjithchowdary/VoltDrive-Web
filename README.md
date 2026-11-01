# VoltDrive Web

This is a separate browser version of VoltDrive. The original Java Swing project in `../VoltDrive-Java-Final/VoltDrive` is not modified.

## Run locally

Requires JDK 21 or newer. From this folder:

```powershell
javac --release 21 -d backend/out backend/src/VoltDriveServer.java
java -cp backend/out VoltDriveServer
```

Open http://localhost:8080. Without `DATABASE_URL`, the server uses an in-memory development store and seeds three demo users:

| Role | Email | Password |
|---|---|---|
| Customer | demo@voltdrive.local | Demo@1234 |
| Station Owner | owner@voltdrive.local | Owner@123 |
| Admin | admin@voltdrive.local | Admin@123 |

For persistent storage, set `DATABASE_URL` to a PostgreSQL connection string and make the PostgreSQL JDBC driver available on the classpath. The Docker deployment does this automatically.

## Render deployment

1. Create a GitHub repository and upload this `VoltDrive-Web` folder.
2. In Render, choose **New > Blueprint**, connect the repository, and select `render.yaml`.
3. Render creates the Docker web service and managed PostgreSQL database. No password or API key is committed; Render supplies `DATABASE_URL`.
4. Wait for the `/api/health` check to pass, then open the generated `.onrender.com` URL.

The service listens on Render's `PORT`, serves the frontend and API from one origin, and creates its tables on first startup. Render web services must bind to `0.0.0.0`; this server does so explicitly.

## Features

Responsive customer, station-owner and admin dashboards; PBKDF2 password hashing; role-based API checks; PostgreSQL persistence; station CRUD; slot-capacity validation; booking history; admin overview; browser geolocation; OpenStreetMap station map; OSRM driving route with Google Maps fallback; bundled fonts and VoltDrive assets.

## Viva points

- The REST API is implemented with the JDK `HttpServer`, so the project has no Maven or framework dependency.
- PostgreSQL is selected when `DATABASE_URL` and the JDBC driver are present; local fallback keeps demonstrations simple.
- Every booking is checked against station port capacity before insertion.
- Passwords are never stored directly: each account has a random salt and PBKDF2-HMAC-SHA256 hash.
- The original Swing application remains a separate, untouched deliverable.
