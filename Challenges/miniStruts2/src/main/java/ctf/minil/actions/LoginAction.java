package ctf.minil.actions;

import com.opensymphony.xwork2.ActionContext;
import com.opensymphony.xwork2.ActionSupport;
import ctf.minil.models.User;
import ctf.minil.utils.Serialize;
import ctf.minil.configs.Config;
import org.apache.struts2.dispatcher.HttpParameters;
import org.apache.struts2.interceptor.ServletResponseAware;
import org.apache.struts2.interceptor.ServletRequestAware;


import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Objects;
import java.util.Set;

public class LoginAction extends ActionSupport implements ServletResponseAware, ServletRequestAware {
    private String username;
    private String password;

    public String getPassword() {
        return password;
    }

    public String getUsername() {
        return username;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String execute() throws IOException {
        ActionContext context = ActionContext.getContext();
        HttpParameters parameters = context.getParameters();
        Set<String> keys = parameters.keySet();
        for (String key : keys) {
            if (Objects.equals(key, "username")) {
                this.username = String.valueOf(parameters.get(key));
            }
            if (Objects.equals(key, "password")) {
                this.password = String.valueOf(parameters.get(key));
            }
        }

        if (!Objects.equals(this.username, null) && !Objects.equals(this.password, null)) {
            User new_user = new User(this.username, this.password);
            Serialize serializer = new Serialize();
            byte[] serialize_user = serializer.serialize(new_user);
            String token = Base64.getEncoder().encodeToString(serialize_user);

            try {
                Config conf = new Config();
                javax.crypto.SecretKey secretKey = new javax.crypto.spec.SecretKeySpec(conf.getSecretKey().getBytes(), "AES");
                javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, secretKey, new javax.crypto.spec.IvParameterSpec(conf.getIV().getBytes(StandardCharsets.UTF_8)));
                byte[] byteEncode = token.getBytes(StandardCharsets.UTF_8);
                byte[] byteAES = cipher.doFinal(byteEncode);
                token = Base64.getEncoder().encodeToString(byteAES);
            } catch (Exception e) {
                return ERROR;
            }

            Cookie div = new Cookie("token", token);
            div.setMaxAge(60 * 60 * 24 * 365);
            servletResponse.addCookie(div);
            return LOGIN;
        }
        return SUCCESS;
    }

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
}
