import java.util.Map;

public class Round3Input {
    public final Map<Integer, Crypto.ShamirPoint> nskShares;
    public final Map<Integer, Crypto.ShamirPoint> betaShares;

    public Round3Input(Map<Integer, Crypto.ShamirPoint> nskShares, 
                       Map<Integer, Crypto.ShamirPoint> betaShares) {
        this.nskShares = nskShares;
        this.betaShares = betaShares;
    }
}