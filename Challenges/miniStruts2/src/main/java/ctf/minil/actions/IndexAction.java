package ctf.minil.actions;

import com.opensymphony.xwork2.ActionSupport;
import org.apache.struts2.interceptor.ServletResponseAware;
import org.apache.struts2.interceptor.ServletRequestAware;
import ctf.minil.utils.Unserialize;
import ctf.minil.configs.Config;
import ctf.minil.models.User;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.Base64;

public class IndexAction extends ActionSupport implements ServletResponseAware, ServletRequestAware {
    private String id;
    private String link;
    private String username;
    protected HttpServletResponse servletResponse;

    @Override
    public void setServletResponse(HttpServletResponse servletResponse) {
        this.servletResponse = servletResponse;
    }

    protected HttpServletRequest servletRequest;

    @Override
    public void setServletRequest(HttpServletRequest servletRequest) {
        this.servletRequest = servletRequest;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getUsername() {
        return username;
    }

    public String getLink() {
        return link;
    }

    public void setLink(String link) {
        this.link = link;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        if(id.contains("exec") || id.contains("\\u")){
            this.id = "no";
            return;
        }
        this.id = id;
        this.link = "./asserts/" + this.id + ".jpg";
    }

    @Override
    public String execute() throws IOException, ClassNotFoundException {

        String token = "";

        for (Cookie c : servletRequest.getCookies()) {
            if (c.getName().equals("token")) {
                token = c.getValue();
            }
        }

        if (Objects.equals(token, "")) {
            return LOGIN;
        }

        try {
            Config conf = new Config();
            javax.crypto.SecretKey secretKey = new javax.crypto.spec.SecretKeySpec(conf.getSecretKey().getBytes(), "AES");
            javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(javax.crypto.Cipher.DECRYPT_MODE, secretKey, new javax.crypto.spec.IvParameterSpec(conf.getIV().getBytes(StandardCharsets.UTF_8)));
            byte[] byteContent = Base64.getDecoder().decode(token);
            byte[] byteDecode = cipher.doFinal(byteContent);
            token = new String(byteDecode);
        } catch (Exception e) {
            return ERROR;
        }

        Unserialize unserializer = new Unserialize();
        User user = (User) unserializer.unserialize(token);
        this.username = user.getUsername();

        return SUCCESS;
    }


}
