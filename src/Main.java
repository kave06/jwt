import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.lang.JoseException;


public class Main {

    public static void main(String[] args) throws JoseException, MalformedClaimException {

        TestJWT.testJWT();
    }
}
