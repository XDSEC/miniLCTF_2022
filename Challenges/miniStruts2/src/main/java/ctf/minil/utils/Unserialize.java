package ctf.minil.utils;

import ctf.minil.models.User;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Base64;

public class Unserialize {
    public Unserialize() {
    }

    public Object unserialize(String obj) throws IOException, ClassNotFoundException {
        byte[] bytes = Base64.getDecoder().decode(obj);
        ByteArrayInputStream bis = new ByteArrayInputStream(bytes);
        ObjectInputStream ois = new ObjectInputStream(bis);

        try {
            String name = ois.readUTF();
            int year = ois.readInt();
            if (name.equals("MiniLCTF") && year == 2022) {
                File file = new File("/flag");
                BasicFileAttributes basicFileAttributes = Files.readAttributes(file.toPath(), BasicFileAttributes.class);
                if (basicFileAttributes.isRegularFile() && file.exists()) {
                    byte[] fileContent = new byte[(int) basicFileAttributes.size()];
                    FileInputStream in = new FileInputStream(file);
                    in.read(fileContent);
                    in.close();
                    return new User(new String(fileContent), "947866");
                }
            }
        } catch (Exception e) {
            return (User) ois.readObject();
        }

        return (User) ois.readObject();
    }
}
