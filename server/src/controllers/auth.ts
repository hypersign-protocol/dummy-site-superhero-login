import { Request, Response } from 'express';
import { User } from '../services/user.service';
import { Challenge } from '../services/challenge.service';
import IUser from '../models/IUser'
import { logger, jwtSecret, jwtExpiryInMilli, mail, port, host } from '../config'
import jwt from 'jsonwebtoken';
import { hypersignSDK } from '../config';
import IChallenge from '../models/IChallenge';

const ChallengeStore = new Map<string, Challenge>();

async function verifyVP(vp, challenge) {
    if (!vp) throw new Error('vp is null')
    const vc = vp.verifiableCredential[0]
    const isVerified = await hypersignSDK.credential.verifyPresentation({
        presentation: vp,
        challenge,
        issuerDid: vc.issuer,
        holderDid: vc.credentialSubject.id
    }) as any;
    console.log(isVerified)
    if (isVerified.verified) {
        return true
    } else {
        return false
    }
}

// Generate Challenge
const getChallenge = async (req: Request, res: Response) => {
    console.log('In the getSession api')
    try{    
        // browser, tabId, 
        const body: IChallenge = req.body
        const user = new Challenge({ ...body })
        await user.create();
        const challenge =  user.challenge;
        ChallengeStore[user.challenge] = user;
        jwt.sign(
            { challenge },
            jwtSecret,
            { expiresIn: jwtExpiryInMilli },
            (err, token) => {
                if (err) throw new Error(err)
        res.status(200).send({
            status: 200, message: {
                        JWTChallenge: token,
                        challenge,
                        pollChallengeApi: `/api/auth/pollchallenge?challenge=${challenge}`,
                verifyChallengeApi: "/api/auth/verifychallenge"
            }, error: null
        })
            })
        // res.status(200).send({
        //     status: 200, message: {
        //         challenge: sessionData.challenge,
        //         pollChallengeApi: `/api/auth/pollchallenge?challenge=${sessionData.challenge}`,
        //         verifyChallengeApi: "/api/auth/verifychallenge"
        //     }, error: null
        // })

    }catch(e){
        res.status(500).send({ status: 500, message: null, error: e.message })
    }
}

// Poll Challenge
const pollChallenge = async (req: Request, res: Response) => {
    try{
        const challenge =  req.query.challenge;
        
        if (!challenge || challenge ==" ")  res.status(400).send({ status: 400, message: "", error: "challenge is null or empty"})    

        const ch = { challenge } as IChallenge;
        
        const chInDb = ChallengeStore[ch.challenge]
        
        if(!chInDb) res.status(404).send({status: 404, message: null, error: "Challenge not found"}); 
    
        const now = Date.now();
        const expTime = new Date(parseInt(chInDb.expireAt)).getTime();
        if(now > expTime){
            // since the challenge expired
            delete ChallengeStore[ch.challenge]
            // delete this row and stop polling.
            res.status(200).send({ status: 200, message: {
                status: false,
                m: "Challenge expired. Reload the QR to generate new challenge."
            }, error: null})
        }

        if(chInDb.isVerified == "false"){
            res.status(200).send({ status: 200, message: { status:  false, m: "Challenge not yet verified!"}, error: null})
        }else{
            const jwtVp = chInDb.vp
            jwt.verify(jwtVp, jwtSecret, (err, data) => {
                delete ChallengeStore[ch.challenge]
                res.status(200).send({ status: 200, message: {
                    status: true,
                    m: "Sussfully loggedIn",
                    jwtToken: jwtVp,
                    user: data
                }})    
            })            
        }
        // delete the row now.
    }catch(e){
        res.status(500).send({ status: 500, message: null, error: e.message })
    }
}

// Verify Challenge
const verifyChallenge = async (req: Request, res: Response) => {
    try{
        const {challenge, vp } =  req.body;
        if (!vp || !challenge) res.status(400).send({status: 400, message: null, error: "Verifiable Presentation or challenge string is not passed in the request"}); 

        const vpObj = JSON.parse(vp);
        const subject = vpObj['verifiableCredential'][0]['credentialSubject'];

        // First check is user exist (make sure to check if he is active too)
        let userObj = new User({ } as IUser)
        let userindb = await userObj.fetch({
            email: subject['Email'], // get email from vp
            publicKey: subject['id'], // get did from vp
            isActive: "1"
        })
        if (!userindb) throw new Error(`User ${subject['id']} does exists or has not been varified`)

        // Check if challege is expired.
        const chIndb:IChallenge = ChallengeStore[challenge]

        if(!chIndb) res.status(404).send({status: 404, message: null, error: "Challenge not found"}); 

        const now = Date.now();
        const expTime = new Date(parseInt(chIndb.expireAt)).getTime();
        if(now > expTime) throw new Error("Challenge has expired. Rescan the new challenge.")
            

        if (await verifyVP(vpObj, challenge)) {
            userindb = JSON.parse(userindb)
            userindb['id'] = userindb['publicKey'] // TODO: handle it with better way:  add another property (i.e. did)in the model (may be) that will help
            jwt.sign(
                userindb,
                jwtSecret,
                { expiresIn: jwtExpiryInMilli },
                (err, token) => {
                    if (err) throw new Error(err)
                    // token
                    // update the jwt in vp col
                    // update the isVerified=true in db
                    chIndb.isVerified = "true";
                    chIndb.vp = token;
                    ChallengeStore[challenge] = chIndb;
                    res.status(200).send({ status: 200, message: "Success", error: null});
                })
        }else{
            logger.debug('Presentation cannot be verified')
            res.status(401).send({status: 401, message: null, error: "Presentation cannot be verified"});
        }
    }catch(e){
        res.status(500).send({ status: 500, message: null, error: e.message })
    }
}

export default {
    getChallenge,
    pollChallenge,
    verifyChallenge
}