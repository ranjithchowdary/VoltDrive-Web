import com.sun.net.httpserver.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.sql.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;

/** VoltDrive web backend. JDK HttpServer keeps the student project dependency-light. */
public final class VoltDriveServer {
    static final int PORT = Integer.parseInt(System.getenv().getOrDefault("PORT", "8080"));
    static final String FRONTEND = System.getenv().getOrDefault("FRONTEND_DIR", "frontend");
    static final Store DB = new Store();
    static final Map<String, Session> SESSIONS = new ConcurrentHashMap<>();
    static final SecureRandom RANDOM = new SecureRandom();

    public static void main(String[] args) throws Exception {
        DB.init();
        HttpServer server = HttpServer.create(new InetSocketAddress("0.0.0.0", PORT), 0);
        server.createContext("/api/", VoltDriveServer::api);
        server.createContext("/", VoltDriveServer::staticFile);
        server.setExecutor(Executors.newFixedThreadPool(16));
        server.start();
        System.out.println("VoltDrive Web listening on http://localhost:" + PORT);
    }

    static void api(HttpExchange x) throws IOException {
        addCors(x);
        if ("OPTIONS".equalsIgnoreCase(x.getRequestMethod())) { send(x, 204, ""); return; }
        String path=x.getRequestURI().getPath(), method=x.getRequestMethod();
        try {
            if (path.equals("/api/health")) { sendJson(x,200,"{\"status\":\"ok\",\"database\":"+quote(DB.mode)+"}"); return; }
            if (path.equals("/api/auth/register") && method.equals("POST")) { register(x); return; }
            if (path.equals("/api/auth/login") && method.equals("POST")) { login(x); return; }
            if (path.equals("/api/auth/logout") && method.equals("POST")) { SESSIONS.remove(sessionId(x)); sendJson(x,200,"{\"ok\":true}"); return; }
            User user=requireUser(x); if(user==null)return;
            if (path.equals("/api/me")) { sendJson(x,200,userJson(user)); return; }
            if (path.equals("/api/stations") && method.equals("GET")) { sendJson(x,200,DB.stationsJson(user)); return; }
            if (path.equals("/api/stations") && method.equals("POST")) { requireRole(user,"Station Owner"); stationCreate(x,user); return; }
            if (path.matches("/api/stations/\\d+") && method.equals("PUT")) { requireRole(user,"Station Owner"); stationUpdate(x,user,id(path)); return; }
            if (path.matches("/api/stations/\\d+") && method.equals("DELETE")) { requireRole(user,"Station Owner"); DB.deleteStation(user,id(path)); sendJson(x,200,"{\"ok\":true}"); return; }
            if (path.equals("/api/bookings") && method.equals("GET")) { sendJson(x,200,DB.bookingsJson(user)); return; }
            if (path.equals("/api/bookings") && method.equals("POST")) { requireRole(user,"Customer"); bookingCreate(x,user); return; }
            if (path.matches("/api/bookings/\\d+") && method.equals("PATCH")) { bookingUpdate(x,user,id(path)); return; }
            if (path.equals("/api/admin/overview")) { requireRole(user,"Admin"); sendJson(x,200,DB.overviewJson()); return; }
            if (path.equals("/api/admin/users")) { requireRole(user,"Admin"); sendJson(x,200,DB.usersJson()); return; }
            if (path.equals("/api/admin/stations")) { requireRole(user,"Admin"); sendJson(x,200,DB.stationsJson(user)); return; }
            if (path.equals("/api/admin/bookings")) { requireRole(user,"Admin"); sendJson(x,200,DB.bookingsJson(user)); return; }
            sendJson(x,404,"{\"error\":\"Not found\"}");
        } catch (AuthError e) { sendJson(x,e.code,"{\"error\":"+quote(e.getMessage())+"}"); }
          catch (Exception e) { e.printStackTrace(); sendJson(x,500,"{\"error\":\"Server error\"}"); }
    }

    static void register(HttpExchange x) throws Exception {
        Map<String,String> f=form(x); String name=f.getOrDefault("name","").trim(), email=f.getOrDefault("email","").trim().toLowerCase(), phone=f.getOrDefault("phone","").trim(), pass=f.getOrDefault("password","");
        if(name.isBlank()||!email.matches("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$")||pass.length()<8) throw new AuthError(400,"Name, valid email and 8+ character password are required");
        if(!phone.replaceAll("[ -]","").matches("^(\\+91)?[6-9]\\d{9}$")) throw new AuthError(400,"A valid Indian mobile number is required");
        String role=f.getOrDefault("role","Customer"); if(!role.equals("Customer")&&!role.equals("Station Owner")) role="Customer";
        if(DB.findUser(email)!=null) throw new AuthError(409,"Email is already registered");
        User u=DB.createUser(name,email,phone,role,pass); sendJson(x,201,"{\"ok\":true,\"user\":"+userJson(u)+"}");
    }
    static void login(HttpExchange x) throws Exception {
        Map<String,String> f=form(x); User u=DB.findUser(f.getOrDefault("email","").trim().toLowerCase());
        if(u==null||!verify(f.getOrDefault("password",""),u.salt,u.hash)) throw new AuthError(401,"Invalid email or password");
        String sid=token(); SESSIONS.put(sid,new Session(u.email,Instant.now().plus(Duration.ofHours(12)))); x.getResponseHeaders().add("Set-Cookie","VD_SESSION="+sid+"; Path=/; HttpOnly; SameSite=Lax"); sendJson(x,200,userJson(u));
    }
    static void stationCreate(HttpExchange x,User u) throws Exception { Map<String,String> f=form(x); Station s=DB.createStation(u.email,f); sendJson(x,201,stationJson(s)); }
    static void stationUpdate(HttpExchange x,User u,int id) throws Exception { Map<String,String> f=form(x); Station s=DB.updateStation(u,id,f); sendJson(x,200,stationJson(s)); }
    static void bookingCreate(HttpExchange x,User u) throws Exception { Map<String,String> f=form(x); Booking b=DB.createBooking(u,f); sendJson(x,201,bookingJson(b)); }
    static void bookingUpdate(HttpExchange x,User u,int id) throws Exception { Map<String,String> f=form(x); Booking b=DB.updateBooking(u,id,f); sendJson(x,200,bookingJson(b)); }

    static User requireUser(HttpExchange x) throws IOException { Session s=SESSIONS.get(sessionId(x)); if(s==null||s.expires.isBefore(Instant.now())){sendJson(x,401,"{\"error\":\"Login required\"}");return null;} User u=DB.findUser(s.email); if(u==null){sendJson(x,401,"{\"error\":\"Login required\"}");return null;} return u; }
    static void requireRole(User u,String role){if(!u.role.equals(role))throw new AuthError(403,"This role cannot perform that action");}
    static String sessionId(HttpExchange x){String c=x.getRequestHeaders().getFirst("Cookie");if(c==null)return "";for(String p:c.split(";")){String[] a=p.trim().split("=",2);if(a.length==2&&a[0].equals("VD_SESSION"))return a[1];}return "";}
    static Map<String,String> form(HttpExchange x)throws IOException{String b=new String(x.getRequestBody().readAllBytes(),StandardCharsets.UTF_8);Map<String,String> m=new HashMap<>();for(String p:b.split("&")){if(p.isBlank())continue;String[] a=p.split("=",2);m.put(URLDecoder.decode(a[0],StandardCharsets.UTF_8),a.length>1?URLDecoder.decode(a[1],StandardCharsets.UTF_8):"");}return m;}
    static int id(String p){return Integer.parseInt(p.substring(p.lastIndexOf('/')+1));}
    static String token(){byte[] b=new byte[32];RANDOM.nextBytes(b);return HexFormat.of().formatHex(b);}
    static String quote(String s){return "\""+(s==null?"":s.replace("\\","\\\\").replace("\"","\\\""))+"\"";}
    static String userJson(User u){return "{\"name\":"+quote(u.name)+",\"email\":"+quote(u.email)+",\"phone\":"+quote(u.phone)+",\"role\":"+quote(u.role)+"}";}
    static String stationJson(Station s){return "{\"id\":"+s.id+",\"ownerEmail\":"+quote(s.ownerEmail)+",\"name\":"+quote(s.name)+",\"address\":"+quote(s.address)+",\"ports\":"+s.ports+",\"connector\":"+quote(s.connector)+",\"price\":"+s.price+",\"status\":"+quote(s.status)+",\"lat\":"+s.lat+",\"lng\":"+s.lng+"}";}
    static String bookingJson(Booking b){return "{\"id\":"+b.id+",\"stationId\":"+b.stationId+",\"stationName\":"+quote(b.stationName)+",\"customerEmail\":"+quote(b.customerEmail)+",\"date\":"+quote(b.date)+",\"slot\":"+quote(b.slot)+",\"energyKwh\":"+b.energy+",\"amount\":"+b.amount+",\"status\":"+quote(b.status)+",\"payment\":"+quote(b.payment)+"}";}
    static void sendJson(HttpExchange x,int code,String body)throws IOException{x.getResponseHeaders().set("Content-Type","application/json; charset=utf-8");send(x,code,body);}
    static void send(HttpExchange x,int code,String body)throws IOException{byte[] b=body.getBytes(StandardCharsets.UTF_8);x.sendResponseHeaders(code,b.length);try(OutputStream o=x.getResponseBody()){o.write(b);}}
    static void addCors(HttpExchange x){x.getResponseHeaders().set("Access-Control-Allow-Origin",x.getRequestHeaders().getFirst("Origin")==null?"*":x.getRequestHeaders().getFirst("Origin"));x.getResponseHeaders().set("Access-Control-Allow-Credentials","true");x.getResponseHeaders().set("Access-Control-Allow-Headers","Content-Type, X-Requested-With");x.getResponseHeaders().set("Access-Control-Allow-Methods","GET,POST,PUT,PATCH,DELETE,OPTIONS");}
    static void staticFile(HttpExchange x)throws IOException{String p=x.getRequestURI().getPath();if(p.equals("/"))p="/index.html";Path file=Paths.get(FRONTEND,p.substring(1)).normalize();Path root=Paths.get(FRONTEND).toAbsolutePath().normalize();if(!file.toAbsolutePath().normalize().startsWith(root)||!Files.exists(file)){file=root.resolve("index.html");}String type=Files.probeContentType(file);if(type==null)type="application/octet-stream";x.getResponseHeaders().set("Content-Type",type);byte[] b=Files.readAllBytes(file);x.sendResponseHeaders(200,b.length);try(OutputStream o=x.getResponseBody()){o.write(b);}}

    static boolean verify(String p,String salt,String expected){try{PBEKeySpec spec=new PBEKeySpec(p.toCharArray(),HexFormat.of().parseHex(salt),210000,256);byte[] h=SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();spec.clearPassword();return MessageDigest.isEqual(HexFormat.of().formatHex(h).getBytes(StandardCharsets.UTF_8),expected.getBytes(StandardCharsets.UTF_8));}catch(Exception e){return false;}}
    static String hash(String p,String salt){try{PBEKeySpec spec=new PBEKeySpec(p.toCharArray(),HexFormat.of().parseHex(salt),210000,256);byte[] h=SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();spec.clearPassword();return HexFormat.of().formatHex(h);}catch(Exception e){throw new IllegalStateException(e);}}
    static String salt(){byte[] b=new byte[16];RANDOM.nextBytes(b);return HexFormat.of().formatHex(b);}

    record Session(String email,Instant expires) {}
    static final class AuthError extends RuntimeException { final int code; AuthError(int c,String m){super(m);code=c;} }
    static final class User {String name,email,phone,role,salt,hash;User(String n,String e,String p,String r,String s,String h){name=n;email=e;phone=p;role=r;salt=s;hash=h;}}
    static final class Station {int id,ports;String ownerEmail,name,address,connector,status;double price,lat,lng;}
    static final class Booking {int id,stationId;String customerEmail,stationName,date,slot,status="Confirmed",payment="Pending";double energy,amount;}

    static final class Store {
        final Map<String,User> users=new ConcurrentHashMap<>(); final List<Station> stations=new CopyOnWriteArrayList<>(); final List<Booking> bookings=new CopyOnWriteArrayList<>();
        Connection c; String mode="memory";
        void init() throws Exception {String url=System.getenv("DATABASE_URL");if(url!=null&&!url.isBlank()){try{Class.forName("org.postgresql.Driver");c=connect(url);schema();mode="postgres";}catch(Exception e){System.err.println("Database unavailable; using memory fallback: "+e.getMessage());}}if(c==null)seedMemory();}
        Connection connect(String raw)throws Exception {if(raw.startsWith("jdbc:"))return DriverManager.getConnection(raw,System.getenv("DB_USER"),System.getenv("DB_PASSWORD"));URI u=URI.create(raw);String jdbc="jdbc:postgresql://"+u.getHost()+(u.getPort()>0?":"+u.getPort():"")+u.getPath();Properties p=new Properties();if(u.getUserInfo()!=null){String[] a=u.getUserInfo().split(":",2);p.setProperty("user",URLDecoder.decode(a[0],StandardCharsets.UTF_8));if(a.length>1)p.setProperty("password",URLDecoder.decode(a[1],StandardCharsets.UTF_8));}return DriverManager.getConnection(jdbc,p);}
        void schema()throws SQLException{try(Statement s=c.createStatement()){s.execute("create table if not exists users(id serial primary key,name text not null,email text unique not null,phone text,role text not null,salt text not null,password_hash text not null,created_at timestamptz default now());");s.execute("create table if not exists stations(id serial primary key,owner_email text not null references users(email),name text not null,address text not null,ports int not null,connector text not null,price numeric not null,status text not null,lat double precision,lng double precision); ");s.execute("create table if not exists bookings(id serial primary key,station_id int not null references stations(id),customer_email text not null references users(email),date_text text not null,slot text not null,energy numeric not null,amount numeric not null,status text not null,payment text not null,unique(station_id,date_text,slot,customer_email));");}}
        void seedMemory(){try{if(users.isEmpty()){createUser("Demo Customer","demo@voltdrive.local","9876543210","Customer","Demo@1234");createUser("Demo Owner","owner@voltdrive.local","9123456780","Station Owner","Owner@123");createUser("System Admin","admin@voltdrive.local","9999999999","Admin","Admin@123");Map<String,String> f=new HashMap<>();f.put("name","VOLT DRIVE MG Road");f.put("address","MG Road, Bengaluru");f.put("ports","6");f.put("connector","CCS2");f.put("price","18");f.put("lat","12.9756");f.put("lng","77.6068");f.put("status","Active");createStation("owner@voltdrive.local",f);}}catch(Exception e){throw new IllegalStateException(e);}}
        User findUser(String e){if(c==null)return users.get(e);try(PreparedStatement p=c.prepareStatement("select name,email,phone,role,salt,password_hash from users where email=?")){p.setString(1,e);try(ResultSet r=p.executeQuery()){return r.next()?new User(r.getString(1),r.getString(2),r.getString(3),r.getString(4),r.getString(5),r.getString(6)):null;}}catch(SQLException x){throw new RuntimeException(x);}}
        User createUser(String n,String e,String ph,String role,String pw){String s=salt();User u=new User(n,e,ph,role,s,hash(pw,s));if(c==null){users.put(e,u);return u;}try(PreparedStatement p=c.prepareStatement("insert into users(name,email,phone,role,salt,password_hash) values(?,?,?,?,?,?)")){p.setString(1,n);p.setString(2,e);p.setString(3,ph);p.setString(4,role);p.setString(5,s);p.setString(6,u.hash);p.executeUpdate();return u;}catch(SQLException x){throw new RuntimeException(x);}}
        Station createStation(String owner,Map<String,String> f)throws Exception{Station s=stationFrom(0,owner,f);if(c==null){s.id=stations.size()+1;stations.add(s);return s;}try(PreparedStatement p=c.prepareStatement("insert into stations(owner_email,name,address,ports,connector,price,status,lat,lng) values(?,?,?,?,?,?,?,?,?)",Statement.RETURN_GENERATED_KEYS)){setStation(p,s);p.executeUpdate();try(ResultSet r=p.getGeneratedKeys()){r.next();s.id=r.getInt(1);}return s;}}
        Station updateStation(User u,int id,Map<String,String> f)throws Exception{Station s=station(id);if(s==null||(!s.ownerEmail.equals(u.email)&&!u.role.equals("Admin")))throw new AuthError(404,"Station not found");Station n=stationFrom(id,s.ownerEmail,f);if(c==null){stations.remove(s);stations.add(n);return n;}try(PreparedStatement p=c.prepareStatement("update stations set name=?,address=?,ports=?,connector=?,price=?,status=?,lat=?,lng=? where id=?")){p.setString(1,n.name);p.setString(2,n.address);p.setInt(3,n.ports);p.setString(4,n.connector);p.setDouble(5,n.price);p.setString(6,n.status);p.setDouble(7,n.lat);p.setDouble(8,n.lng);p.setInt(9,id);p.executeUpdate();return n;}}
        void deleteStation(User u,int id){Station s=station(id);if(s==null||(!s.ownerEmail.equals(u.email)&&!u.role.equals("Admin")))throw new AuthError(404,"Station not found");if(c==null){stations.remove(s);return;}try(PreparedStatement p=c.prepareStatement("delete from stations where id=?")){p.setInt(1,id);p.executeUpdate();}catch(SQLException x){throw new RuntimeException(x);}}
        Booking createBooking(User u,Map<String,String> f)throws Exception{int sid=Integer.parseInt(f.getOrDefault("stationId","0"));Station s=station(sid);if(s==null)throw new AuthError(404,"Station not found");String date=f.getOrDefault("date","");String slot=f.getOrDefault("slot","");long count=bookingsFor(sid,date,slot);if(count>=s.ports)throw new AuthError(409,"That charging slot is full");Booking b=new Booking();b.stationId=sid;b.stationName=s.name;b.customerEmail=u.email;b.date=date;b.slot=slot;b.energy=Double.parseDouble(f.getOrDefault("energyKwh","0"));b.amount=b.energy*s.price;if(c==null){b.id=bookings.size()+1;bookings.add(b);return b;}try(PreparedStatement p=c.prepareStatement("insert into bookings(station_id,customer_email,date_text,slot,energy,amount,status,payment) values(?,?,?,?,?,?,?,?)",Statement.RETURN_GENERATED_KEYS)){p.setInt(1,b.stationId);p.setString(2,b.customerEmail);p.setString(3,b.date);p.setString(4,b.slot);p.setDouble(5,b.energy);p.setDouble(6,b.amount);p.setString(7,b.status);p.setString(8,b.payment);p.executeUpdate();try(ResultSet r=p.getGeneratedKeys()){r.next();b.id=r.getInt(1);}return b;}}
        Booking updateBooking(User u,int id,Map<String,String> f)throws Exception{Booking b=booking(id);if(b==null||(!b.customerEmail.equals(u.email)&&!u.role.equals("Admin")&&!u.role.equals("Station Owner")))throw new AuthError(404,"Booking not found");String status=f.getOrDefault("status",b.status),payment=f.getOrDefault("payment",b.payment);if(c==null){b.status=status;b.payment=payment;return b;}try(PreparedStatement p=c.prepareStatement("update bookings set status=?,payment=? where id=?")){p.setString(1,status);p.setString(2,payment);p.setInt(3,id);p.executeUpdate();b.status=status;b.payment=payment;return b;}}
        long bookingsFor(int sid,String date,String slot)throws SQLException{if(c==null)return bookings.stream().filter(b->b.stationId==sid&&b.date.equals(date)&&b.slot.equals(slot)&&!b.status.equals("Cancelled")).count();try(PreparedStatement p=c.prepareStatement("select count(*) from bookings where station_id=? and date_text=? and slot=? and status<>'Cancelled'")){p.setInt(1,sid);p.setString(2,date);p.setString(3,slot);try(ResultSet r=p.executeQuery()){r.next();return r.getLong(1);}}}
        Station station(int id){if(c==null)return stations.stream().filter(s->s.id==id).findFirst().orElse(null);try(PreparedStatement p=c.prepareStatement("select id,owner_email,name,address,ports,connector,price,status,lat,lng from stations where id=?")){p.setInt(1,id);try(ResultSet r=p.executeQuery()){return r.next()?readStation(r):null;}}catch(SQLException x){throw new RuntimeException(x);}}
        Booking booking(int id){if(c==null)return bookings.stream().filter(b->b.id==id).findFirst().orElse(null);try(PreparedStatement p=c.prepareStatement("select b.id,b.station_id,s.name,b.customer_email,b.date_text,b.slot,b.energy,b.amount,b.status,b.payment from bookings b join stations s on s.id=b.station_id where b.id=?")){p.setInt(1,id);try(ResultSet r=p.executeQuery()){return r.next()?readBooking(r):null;}}catch(SQLException x){throw new RuntimeException(x);}}
        Station stationFrom(int id,String owner,Map<String,String> f){Station s=new Station();s.id=id;s.ownerEmail=owner;s.name=f.getOrDefault("name","");s.address=f.getOrDefault("address","");s.ports=Integer.parseInt(f.getOrDefault("ports","1"));s.connector=f.getOrDefault("connector","CCS2");s.price=Double.parseDouble(f.getOrDefault("price","0"));s.status=f.getOrDefault("status","Active");s.lat=Double.parseDouble(f.getOrDefault("lat","0"));s.lng=Double.parseDouble(f.getOrDefault("lng","0"));return s;}
        void setStation(PreparedStatement p,Station s)throws SQLException{p.setString(1,s.ownerEmail);p.setString(2,s.name);p.setString(3,s.address);p.setInt(4,s.ports);p.setString(5,s.connector);p.setDouble(6,s.price);p.setString(7,s.status);p.setDouble(8,s.lat);p.setDouble(9,s.lng);}
        Station readStation(ResultSet r)throws SQLException{Station s=new Station();s.id=r.getInt(1);s.ownerEmail=r.getString(2);s.name=r.getString(3);s.address=r.getString(4);s.ports=r.getInt(5);s.connector=r.getString(6);s.price=r.getDouble(7);s.status=r.getString(8);s.lat=r.getDouble(9);s.lng=r.getDouble(10);return s;}
        Booking readBooking(ResultSet r)throws SQLException{Booking b=new Booking();b.id=r.getInt(1);b.stationId=r.getInt(2);b.stationName=r.getString(3);b.customerEmail=r.getString(4);b.date=r.getString(5);b.slot=r.getString(6);b.energy=r.getDouble(7);b.amount=r.getDouble(8);b.status=r.getString(9);b.payment=r.getString(10);return b;}
        String stationsJson(User u){List<Station> a=new ArrayList<>();if(c==null){a.addAll(stations);}else try(Statement st=c.createStatement();ResultSet r=st.executeQuery("select id,owner_email,name,address,ports,connector,price,status,lat,lng from stations order by id")){while(r.next())a.add(readStation(r));}catch(SQLException x){throw new RuntimeException(x);}StringBuilder z=new StringBuilder("[");for(Station s:a){if(z.length()>1)z.append(',');z.append(stationJson(s));}return z.append(']').toString();}
        String bookingsJson(User u){List<Booking> a=new ArrayList<>();if(c==null){for(Booking b:bookings)if(u.role.equals("Admin")||b.customerEmail.equals(u.email)||stations.stream().anyMatch(s->s.id==b.stationId&&s.ownerEmail.equals(u.email)))a.add(b);}else try(PreparedStatement p=c.prepareStatement("select b.id,b.station_id,s.name,b.customer_email,b.date_text,b.slot,b.energy,b.amount,b.status,b.payment from bookings b join stations s on s.id=b.station_id "+(u.role.equals("Admin")?"":"where b.customer_email=? or s.owner_email=?")+" order by b.id desc")){if(!u.role.equals("Admin")){p.setString(1,u.email);p.setString(2,u.email);}try(ResultSet r=p.executeQuery()){while(r.next())a.add(readBooking(r));}}catch(SQLException x){throw new RuntimeException(x);}StringBuilder z=new StringBuilder("[");for(Booking b:a){if(z.length()>1)z.append(',');z.append(bookingJson(b));}return z.append(']').toString();}
        String usersJson(){if(c==null){StringBuilder z=new StringBuilder("[");for(User u:users.values()){if(z.length()>1)z.append(',');z.append(userJson(u));}return z.append(']').toString();}try(Statement s=c.createStatement();ResultSet r=s.executeQuery("select name,email,phone,role,salt,password_hash from users order by email")){StringBuilder z=new StringBuilder("[");while(r.next()){if(z.length()>1)z.append(',');z.append(userJson(new User(r.getString(1),r.getString(2),r.getString(3),r.getString(4),r.getString(5),r.getString(6))));}return z.append(']').toString();}catch(SQLException x){throw new RuntimeException(x);}}
        String overviewJson(){long us=users.size(),ss=stations.size(),bs=bookings.size();if(c!=null)try(Statement s=c.createStatement();ResultSet r=s.executeQuery("select (select count(*) from users),(select count(*) from stations),(select count(*) from bookings)")){r.next();us=r.getLong(1);ss=r.getLong(2);bs=r.getLong(3);}catch(SQLException x){throw new RuntimeException(x);}return "{\"users\":"+us+",\"stations\":"+ss+",\"bookings\":"+bs+"}";}
    }
}
