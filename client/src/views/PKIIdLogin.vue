<style scoped>
.addmargin {
  margin-top: 10px;
  margin-bottom: 10px;
}

.vue-logo-back {
  background-color: black;
}

.logo {
  width: 144px;
}

.fullbody {
  width: 100%;
}
.floatLeft {
  float: left;
}
.floatRight {
  text-align: end;
}
.title {
  color: grey;
}

h5 {
   width: 100%; 
   text-align: center; 
   border-bottom: 1px solid #80808045; 
   line-height: 0.1em;
   margin: 10px 0 20px; 
} 

h5 span { 
    background:#fff; 
    padding:0 10px; 
}
</style>
<template>
  <!-- <div class="row" style="margin-left: 35%;"> -->
  <div class="row" style="align-content: center;">
    <loading :active.sync="isLoading" :can-cancel="true" :is-full-page="fullPage"></loading>
    <div class="col-md-7" style="font-size: small;color:grey;" hidden>
      Can we put one big image here?
    </div>
    <div class="col-md-3" style="font-size: small;color:grey;margin-left: 36%;">
      <form action="#" style="padding:6px">
        <b-card no-body style="padding: 40px">
          <h4>Login</h4>
        <hr/>
          <div class="row">
            <form action="#" class="col-md-12">
              <div class="form-group">
                <qrcode-vue :value="value" :size="200" level="H"></qrcode-vue>
                <label>Scan the QR code using Hypersign App in your mobile phone to authenticate!</label>
              </div>
              <div class="form-group">
              <h5><span>Or</span></h5>
              </div>
              <div class="form-group">
                <label class="floatLeft">Upload keys.json:</label>
                <input
                  type="file"
                  class="form-control"
                  placeholder
                  @change="onFileChange"
                  accept="*.json"
                />
              </div>
              <div class="form-group">
                <label class="floatLeft">Upload vc.json:</label>
                <input type="file" class="form-control" placeholder @change="onFileChange" />
              </div>
            </form>
          </div>
          <div class="row">
            <!-- <div class="col-sm-3" hidden>
              <button
                type="button"
                data-toggle="modal"
                @click="downloadPresentation()"
                class="btn btn-primary btn-sm floatLeft"
              >View Proof</button>
            </div> -->
            <div class="col-sm-3">
              <button
                type="button"
                data-toggle="modal"
                @click="login('PKI')"
                class="btn btn-primary btn-sm floatLeft"
              >Login</button>
            </div>
            <div class="col-md-9 floatRight">
              Do not have an account?
              <a @click="push('register')" style="color:blue; cursor: pointer;">SignUp</a>
            </div>
          </div>
        </b-card>
      </form>
    </div>
  </div>
</template>

<script>
import QrcodeVue from "qrcode.vue";
import conf from '../config';
const { hypersignSDK } = conf;
import Loading from "vue-loading-overlay";
import "vue-loading-overlay/dist/vue-loading.css";
const { sha256hashStr } = require("../utils/hash");
export default {
  name: "Login",
  components: {
    QrcodeVue,
    Loading,
  },
  data() {
    return {
      active: 0,
      username: "",
      password: "",
      host: location.hostname,
      challenge: "dddd",
      domain: location.host,
      credentials: {},
      userData: {},
      value: '',
      user: {},
      verifiablePresentation: "",
      fullPage: true,
      isLoading: false,
      privateKey:
        "3isrtEJ4gt1ZHkdUYYph1WFAtzfqAL5WM6Hh1NC2hmWnDfBypXjt5oUFdAqQdiess2vqqQ3iF6x4fDVuvLw454sn",
      did: "did:hs:892325a4-75c9-465c-882b-91e3ca5143c3",
    };
  },
  created() {
    const url = `${this.$config.studioServer.BASE_URL}${this.$config.studioServer.AUTH_CHALLENGE_EP}`;
    //console.log(url);
    fetch(url)
      .then((res) => res.json())
      .then((json) => {
        //console.log(json);
        if (json.status == 200) {
          this.challenge = {
            challenge: json.message.challenge,
            JWTChallenge: json.message.JWTChallenge
          };
          const baseUrl = this.$config.studioServer.BASE_URL.replace(/\/+$/, "");
          this.value = `${baseUrl}${json.message.verifyChallengeApi}?challenge=${this.challenge.challenge}`
          const pollUrl = `${baseUrl}${json.message.pollChallengeApi}`
          this.poll(pollUrl) 
        }
      })
      .catch((e) => this.notifyErr(`Error: ${e.message}`));
    
  },
  mounted() {
    this.clean();
  },
  methods: {
    async poll(url){
       var _this = this;
      const interval = setInterval(function (){
          fetch(url)
          .then(res => res.json())
          .then(json => {
              if(json.status == 200){
                  if(!json.message.status){
                     // 
                     if(json.message.m.indexOf('expired') > -1){
                        clearInterval(interval)
                        alert('Challenge expired. Please reload this page.')   
                        _this.isLoading = true;
                        setTimeout(() => {
                          _this.isLoading = false;
                          _this.$router.push("login")
                        }, 2000)
                     }else{
                       console.log(json.message.m)
                     }
                  }else{
                    _this.isLoading = true;
                    clearInterval(interval)
                    setTimeout(function (){
                        _this.isLoading = false;
                        console.log('Verifierd! Moving to login page...')
                        // go to home page
                        localStorage.setItem("authToken",json.message.jwtToken);
                        localStorage.setItem("user", JSON.stringify(json.message.user));
                        if (localStorage.getItem("authToken") != null) {
                          if (_this.$route.params.nextUrl != null) {
                            _this.$router.push(_this.$route.params.nextUrl);
                          } else {
                            _this.$router.push("dashboard");
                          }
                        }
                    }, 2000)
                    
                  }
              }else{
                  clearInterval(interval)
                  alert(`Error: ${json.message.error}`)
              }
          })
          .catch(e => {
              clearInterval(interval)
              alert(`Error: ${e.message}`)
          })
      }, 5000)
    },
    push(path){
      this.$router.push(path)
    },
    clean() {
      localStorage.removeItem("authToken");
      localStorage.removeItem("user");
      localStorage.removeItem("credentials");
      localStorage.removeItem("userData");
    },
    notifySuccess(msg) {
      this.$notify({
        group: "foo",
        title: "Information",
        type: "success",
        text: msg,
      });
    },
    notifyErr(msg) {
      this.$notify({
        group: "foo",
        title: "Error",
        type: "error",
        text: msg,
      });
    },
    gotosubpage: (id) => {
      this.$router.push(`${id}`);
    },
    async generatePresentation() {  
      // try{
        const keys = JSON.parse(localStorage.getItem("keys"));
        //console.log(keys)
        this.user.privateKey = keys.privateKeyBase58
        this.user.id = keys.publicKey.id
        this.user.did = this.user.id.split('#')[0]
        const vc = JSON.parse(localStorage.getItem("credential"));
        this.user.name = vc['credentialSubject']['Name']
        this.user.email = vc['credentialSubject']['Email']
        // console.log(this.user)
        if(!vc) throw new Error('VC is null')
        //console.log(vc)
        //console.log("Before generating presentation ....")
        const vp_unsigned = await hypersignSDK.credential.generatePresentation(vc, this.user.id);
        //console.log("After generating presentation ....")
        //console.log(vp_unsigned)
        this.notifySuccess("Presentation generated")
        //console.log("Before signing presentation ....")
        const vp_signed = await hypersignSDK.credential.signPresentation(vp_unsigned, this.user.id, this.user.privateKey, this.challenge.challenge)
        //console.log(vp_signed)
        //console.log("After signing presentation ....")
        this.notifySuccess("Presentation signed")
        this.verifiablePresentation = JSON.stringify(vp_signed)
        
        localStorage.removeItem('credential')
        localStorage.removeItem('keys')
      // }catch(e){
      //   this.notifyErr(e.message)
      // }
    },
    async downloadPresentation() {
      await this.generatePresentation()
      this.forceFileDownload(
        this.verifiablePresentation,
        "vp.json"
      );
    },
    forceFileDownload(data, fileName) {
      const url = window.URL.createObjectURL(new Blob([data]));
      const link = document.createElement("a");
      link.href = url;
      link.setAttribute("download", fileName);
      document.body.appendChild(link);
      link.click();
    },
    readFile(file, cb){
      //console.log('Inside reaffileDs')
      const reader = new FileReader();
      reader.onload = cb
      reader.readAsText(file);
    },
    onFileChange(event) {
      const file = event.target.files[0];
      this.readFile(file, this.onfileLoadSuccess)
    },
    onfileLoadSuccess (evt){
        //console.log('Inside callback')
        const fileJSON = JSON.parse(evt.target.result);
        if (!fileJSON) this.notifyErr("Incorrect file");
        if(fileJSON["type"] && fileJSON["type"].find(x => x == 'VerifiableCredential')){
          //console.log('Inside callback: vc')
          localStorage.removeItem('credential')
          localStorage.setItem("credential", JSON.stringify(fileJSON));  
        }else if(fileJSON['privateKeyBase58']){
          //console.log('Inside callback: keys')
          localStorage.removeItem('keys')
          localStorage.setItem("keys", JSON.stringify(fileJSON));  
        }else{
          this.notifyErr("Invalid file")
        }
    },
    async login(type) {
      try {
        this.isLoading = true;
        let url = "";
        let headers = {
          "Content-Type": "application/json",
        };
        
        url = `${this.$config.studioServer.BASE_URL}api/auth/login_pki?type=PKI`;
        headers["x-auth-token"] = this.challenge.JWTChallenge;
        await this.generatePresentation();
        
        const userData = {
          fname: this.user.name,
          email: this.user.email,
          publicKey: this.user.did,
          proof: this.verifiablePresentation,
          challenge: this.challenge ? this.challenge.challenge : "",
          domain: this.domain,
        };

        // console.log(url)
        console.log('.............before fetch')
        fetch(url, {
          body: JSON.stringify(userData),
          method: "POST",
          headers: headers,
        })
          .then((res) => res.json())
          .then((j) => {
            this.isLoading = false;
            if (j && j.status != 200) {
              return this.notifyErr(`Error:  ${j.error}`);
            }

            localStorage.setItem("authToken", j.message.jwtToken);
            j.message.user["privateKey"] = this.user.privateKey;
            localStorage.setItem("user", JSON.stringify(j.message.user));
            if (localStorage.getItem("authToken") != null) {
              if (this.$route.params.nextUrl != null) {
                this.$router.push(this.$route.params.nextUrl);
              } else {
                this.$router.push("dashboard");
              }
            }
          });
      } catch (e) {
        console.log(e)
        this.clean();
        this.isLoading = false;
        this.notifyErr(`Error: ${e.message}`);
      }
    },
  },
};
</script>
