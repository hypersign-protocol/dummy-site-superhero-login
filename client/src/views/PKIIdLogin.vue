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

.download{
  padding: 5px;
}
h5 span { 
    background:#fff; 
    padding:0 10px; 
}
</style>
<template>
  <!-- <div class="row" style="margin-left: 35%;"> -->
  <div class="row" style="align-content: center;">
    <div class="col-md-7" style="font-size: small;color:grey;" hidden>
      Can we put one big image here?
    </div>
    <div class="col-md-4"></div>
    <div class="col-md-3" style="font-size: small;color:grey;">
      <form action="#">
        <b-card no-body style="padding: 12%; border-top: 4px solid #00f9;">
          <loading :active.sync="isLoading" :can-cancel="true" :is-full-page="fullPage"></loading>
        <h4>Login</h4>
        <hr/>
          <div class="row" >
            <form action="#" class="col-md-12">
              <div class="form-group">
                <qrcode-vue :value="value" :size="200" level="H"></qrcode-vue>
                <label style="font-size:larger">Scan the QR code using <a href="https://superhero.com/" target="_blank"> Superhero</a> credential in your mobile app to authenticate!</label>
                <div>
                  <p>Don’t have the app yet? <a href="#">Get it now</a></p>
                  <div>
                    <span class="download">
                      <a href="https://addons.mozilla.org/en-US/firefox/addon/superhero-wallet/" target="_blank"><img src="https://wallet.superhero.com/assets/firefox.4c960eb9612efe497c6476a594a28bd1.svg"/></a>
                    </span>
                    <span class="download">
                      <a href="https://chrome.google.com/webstore/detail/superhero/mnhmmkepfddpifjkamaligfeemcbhdne" target="_blank"><img src="https://wallet.superhero.com/assets/google.f93c6aeccedec4384dda9c1deb9543c0.svg"/></a>
                    </span>
                    <span class="download">
                      <a href="https://testflight.apple.com/join/3o5r4dQQ" target="_blank"><img src="data:image/svg+xml;base64,PHN2ZyBpZD0iR3JvdXBfMTM3NiIgZGF0YS1uYW1lPSJHcm91cCAxMzc2IiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hsaW5rIiB3aWR0aD0iNDAiIGhlaWdodD0iNDAiIHZpZXdCb3g9IjAgMCA0MCA0MCI+CiAgPGRlZnM+CiAgICA8bGluZWFyR3JhZGllbnQgaWQ9ImxpbmVhci1ncmFkaWVudCIgeDE9IjAuNSIgeDI9IjAuNSIgeTI9IjEiIGdyYWRpZW50VW5pdHM9Im9iamVjdEJvdW5kaW5nQm94Ij4KICAgICAgPHN0b3Agb2Zmc2V0PSIwIiBzdG9wLWNvbG9yPSIjMTdjOWZiIi8+CiAgICAgIDxzdG9wIG9mZnNldD0iMSIgc3RvcC1jb2xvcj0iIzFhNzRlOCIvPgogICAgPC9saW5lYXJHcmFkaWVudD4KICA8L2RlZnM+CiAgPGcgaWQ9ImJ1dHRvbiIgdHJhbnNmb3JtPSJ0cmFuc2xhdGUoMCAwKSI+CiAgICA8ZyBpZD0iaW9zIiB0cmFuc2Zvcm09InRyYW5zbGF0ZSgwIDApIj4KICAgICAgPHBhdGggaWQ9IlBhdGhfMTIwMSIgZGF0YS1uYW1lPSJQYXRoIDEyMDEiIGQ9Ik04Ljc2LDBIMzEuMjRBOC43Niw4Ljc2LDAsMCwxLDQwLDguNzZWMzEuMjRBOC43Niw4Ljc2LDAsMCwxLDMxLjI0LDQwSDguNzZBOC43Niw4Ljc2LDAsMCwxLDAsMzEuMjRWOC43NkE4Ljc2LDguNzYsMCwwLDEsOC43NiwwWiIgdHJhbnNmb3JtPSJ0cmFuc2xhdGUoMCAwKSIgZmlsbD0idXJsKCNsaW5lYXItZ3JhZGllbnQpIi8+CiAgICAgIDxwYXRoIGlkPSJQYXRoXzEyMDIiIGRhdGEtbmFtZT0iUGF0aCAxMjAyIiBkPSJNNDMuNjM0LDY4LjQzaDBMNDIuMjcxLDcwLjhhMS44MDgsMS44MDgsMCwxLDEtMy4xMzEtMS44MDhsMS4wMDctMS43NDUuMS0uMTY4YTEuNDkyLDEuNDkyLDAsMCwxLDEuNDUxLS42czIuMDA2LjIxOCwyLjE1MSwxLjI2YTEuMjIsMS4yMiwwLDAsMS0uMjExLjY4NlptMTkuNC02LjA1SDU4Ljc2N2EuNjI5LjYyOSwwLDAsMS0uNDY3LS4xOFY2Mi4ybC00LjU2NS03LjkwN2gtLjAwNmwtLjI3NC0uMzkzYy0uNDQ5LS42ODYtMS4xNjEsMS4wNjktMS4xNjEsMS4wNjktLjg1MSwxLjk1Ni4xMjEsNC4xNzkuNDU5LDQuODUxTDU5LjA5MSw3MC44YTEuODA4LDEuODA4LDAsMSwwLDMuMTMxLTEuODA4bC0xLjU4NS0yLjc0NmMtLjAzMS0uMDY3LS4wODQtLjI0Ny4yNDEtLjI0OGgyLjE1NGExLjgwOCwxLjgwOCwwLDAsMCwwLTMuNjE2Wm0tOC4yODMsMi40NThTNTQuOTc2LDY2LDU0LjEsNjZIMzguMzNhMS44MDgsMS44MDgsMCwxLDEsMC0zLjYxNmg0LjA1M2MuNjU0LS4wMzguODEtLjQxNi44MS0uNDE2aDBMNDguNDg3LDUyLjhoMGEuNC40LDAsMCwwLDAtLjM3MUw0Ni43NCw0OS40YTEuODA4LDEuODA4LDAsMCwxLDMuMTMxLTEuOGwuODEsMS40LjgwOS0xLjRhMS44MDgsMS44MDgsMCwxLDEsMy4xMzEsMS44MDhMNDcuMjU5LDYyLjE1OWMtLjAzMi4wNzgtLjA0Mi4yLjIuMjIxaDQuNHYuMDQzYTIuOTU2LDIuOTU2LDAsMCwxLDIuODg5LDIuNDE0WiIgdHJhbnNmb3JtPSJ0cmFuc2xhdGUoLTMwLjgxNSAtMzkuMzk3KSIgZmlsbD0iI2ZmZiIvPgogICAgPC9nPgogIDwvZz4KPC9zdmc+Cg=="/></a>
                    </span>
                    <span class="download">
                      <a href="https://play.google.com/store/apps/details?id=com.superhero.cordova" target="_blank"><img src="data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hsaW5rIiB3aWR0aD0iMzYuNTAxIiBoZWlnaHQ9IjQwIiB2aWV3Qm94PSIwIDAgMzYuNTAxIDQwIj4KICA8ZGVmcz4KICAgIDxsaW5lYXJHcmFkaWVudCBpZD0ibGluZWFyLWdyYWRpZW50IiB4MT0iMC45MTUiIHkxPSIwLjA1IiB4Mj0iLTAuMzgzIiB5Mj0iMC43MTkiIGdyYWRpZW50VW5pdHM9Im9iamVjdEJvdW5kaW5nQm94Ij4KICAgICAgPHN0b3Agb2Zmc2V0PSIwIiBzdG9wLWNvbG9yPSIjMDBhMGZmIi8+CiAgICAgIDxzdG9wIG9mZnNldD0iMC4wMDciIHN0b3AtY29sb3I9IiMwMGExZmYiLz4KICAgICAgPHN0b3Agb2Zmc2V0PSIwLjI2IiBzdG9wLWNvbG9yPSIjMDBiZWZmIi8+CiAgICAgIDxzdG9wIG9mZnNldD0iMC41MTIiIHN0b3AtY29sb3I9IiMwMGQyZmYiLz4KICAgICAgPHN0b3Agb2Zmc2V0PSIwLjc2IiBzdG9wLWNvbG9yPSIjMDBkZmZmIi8+CiAgICAgIDxzdG9wIG9mZnNldD0iMSIgc3RvcC1jb2xvcj0iIzAwZTNmZiIvPgogICAgPC9saW5lYXJHcmFkaWVudD4KICAgIDxsaW5lYXJHcmFkaWVudCBpZD0ibGluZWFyLWdyYWRpZW50LTIiIHgxPSIxLjA3NiIgeTE9IjAuNSIgeDI9Ii0xLjMwNSIgeTI9IjAuNSIgZ3JhZGllbnRVbml0cz0ib2JqZWN0Qm91bmRpbmdCb3giPgogICAgICA8c3RvcCBvZmZzZXQ9IjAiIHN0b3AtY29sb3I9IiNmZmUwMDAiLz4KICAgICAgPHN0b3Agb2Zmc2V0PSIwLjQwOSIgc3RvcC1jb2xvcj0iI2ZmYmQwMCIvPgogICAgICA8c3RvcCBvZmZzZXQ9IjAuNzc1IiBzdG9wLWNvbG9yPSJvcmFuZ2UiLz4KICAgICAgPHN0b3Agb2Zmc2V0PSIxIiBzdG9wLWNvbG9yPSIjZmY5YzAwIi8+CiAgICA8L2xpbmVhckdyYWRpZW50PgogICAgPGxpbmVhckdyYWRpZW50IGlkPSJsaW5lYXItZ3JhZGllbnQtMyIgeDE9IjAuODYyIiB5MT0iMC4xNzgiIHgyPSItMC41MDEiIHkyPSIxLjk0OCIgZ3JhZGllbnRVbml0cz0ib2JqZWN0Qm91bmRpbmdCb3giPgogICAgICA8c3RvcCBvZmZzZXQ9IjAiIHN0b3AtY29sb3I9IiNmZjNhNDQiLz4KICAgICAgPHN0b3Agb2Zmc2V0PSIxIiBzdG9wLWNvbG9yPSIjYzMxMTYyIi8+CiAgICA8L2xpbmVhckdyYWRpZW50PgogICAgPGxpbmVhckdyYWRpZW50IGlkPSJsaW5lYXItZ3JhZGllbnQtNCIgeDE9Ii0wLjE4OCIgeTE9Ii0wLjU0MiIgeDI9IjAuNDIxIiB5Mj0iMC4yNDkiIGdyYWRpZW50VW5pdHM9Im9iamVjdEJvdW5kaW5nQm94Ij4KICAgICAgPHN0b3Agb2Zmc2V0PSIwIiBzdG9wLWNvbG9yPSIjMzJhMDcxIi8+CiAgICAgIDxzdG9wIG9mZnNldD0iMC4wNjgiIHN0b3AtY29sb3I9IiMyZGE3NzEiLz4KICAgICAgPHN0b3Agb2Zmc2V0PSIwLjQ3NiIgc3RvcC1jb2xvcj0iIzE1Y2Y3NCIvPgogICAgICA8c3RvcCBvZmZzZXQ9IjAuODAxIiBzdG9wLWNvbG9yPSIjMDZlNzc1Ii8+CiAgICAgIDxzdG9wIG9mZnNldD0iMSIgc3RvcC1jb2xvcj0iIzAwZjA3NiIvPgogICAgPC9saW5lYXJHcmFkaWVudD4KICA8L2RlZnM+CiAgPGcgaWQ9InBsYXktc3RvcmUtaWNvbiIgdHJhbnNmb3JtPSJ0cmFuc2xhdGUoMC4wMDYgLTAuMzIzKSI+CiAgICA8cGF0aCBpZD0iUGF0aF8xMjAzIiBkYXRhLW5hbWU9IlBhdGggMTIwMyIgZD0iTS43MzIsMS4xNTZBMy4wODUsMy4wODUsMCwwLDAsMCwzLjM0VjM3LjcyN2EzLjA3NiwzLjA3NiwwLDAsMCwuNzMyLDIuMTg0bC4xMTguMTEyTDIwLjQzMSwyMC43NjJ2LS40NTRMLjg0OSwxLjA0M2wtLjExOC4xMTNaIiB0cmFuc2Zvcm09InRyYW5zbGF0ZSgwIC0wLjIxNSkiIGZpbGw9InVybCgjbGluZWFyLWdyYWRpZW50KSIvPgogICAgPHBhdGggaWQ9IlBhdGhfMTIwNCIgZGF0YS1uYW1lPSJQYXRoIDEyMDQiIGQ9Ik0zNS42MzUsMzIuNjQzLDI5LjExLDI2LjIxOXYtLjQ1NGw2LjUyNy02LjQyMi4xNDkuMDgxLDcuNzMzLDQuMzIyYzIuMjA5LDEuMjM0LDIuMjA5LDMuMjUzLDAsNC40OWwtNy43MzMsNC4zMjFaIiB0cmFuc2Zvcm09InRyYW5zbGF0ZSgtOC42OCAtNS42NzEpIiBmaWxsPSJ1cmwoI2xpbmVhci1ncmFkaWVudC0yKSIvPgogICAgPHBhdGggaWQ9IlBhdGhfMTIwNSIgZGF0YS1uYW1lPSJQYXRoIDEyMDUiIGQ9Ik0yNy40MTYsMzUuMzg0LDIwLjc0LDI4LjgxNywxLjA0Myw0OC4yYy43MjguNzU5LDEuOTMyLjg1MiwzLjI4NC4xTDI3LjQxNiwzNS4zODQiIHRyYW5zZm9ybT0idHJhbnNsYXRlKC0wLjMxMSAtOC40OTcpIiBmaWxsPSJ1cmwoI2xpbmVhci1ncmFkaWVudC0zKSIvPgogICAgPHBhdGggaWQ9IlBhdGhfMTIwNiIgZGF0YS1uYW1lPSJQYXRoIDEyMDYiIGQ9Ik0yNy40MTYsMTMuNzU0LDQuMzI3Ljg0NUMyLjk3NS4wODksMS43NzEuMTgzLDEuMDQzLjk0MUwyMC43NCwyMC4zMmw2LjY3Ni02LjU2OFoiIHRyYW5zZm9ybT0idHJhbnNsYXRlKC0wLjMxMSAwKSIgZmlsbD0idXJsKCNsaW5lYXItZ3JhZGllbnQtNCkiLz4KICAgIDxnIGlkPSJHcm91cF85NzEiIGRhdGEtbmFtZT0iR3JvdXAgOTcxIiB0cmFuc2Zvcm09InRyYW5zbGF0ZSgtMC4wMDUgMjYuNzQ0KSI+CiAgICAgIDxwYXRoIGlkPSJQYXRoXzEyMDciIGRhdGEtbmFtZT0iUGF0aCAxMjA3IiBkPSJNMjcuMjY4LDM3Ljk3LDQuMzI4LDUwLjc5MmMtMS4yODUuNzE5LTIuNDMuNjcxLTMuMTY2LjAxN2wtLjExOC4xMTYuMTE4LjExMWEyLjY2NywyLjY2NywwLDAsMCwzLjE2Ni0uMDE1TDI3LjQxNywzOC4xMTNsLS4xNDgtLjE0M1oiIHRyYW5zZm9ybT0idHJhbnNsYXRlKC0wLjMwNiAtMzcuOTcpIiBvcGFjaXR5PSIwLjIiLz4KICAgICAgPHBhdGggaWQ9IlBhdGhfMTIwOCIgZGF0YS1uYW1lPSJQYXRoIDEyMDgiIGQ9Ik0uNzMyLDU1LjE3N0EzLjA4NSwzLjA4NSwwLDAsMSwwLDUyLjk5M3YuMjI3QTMuMDc2LDMuMDc2LDAsMCwwLC43MzIsNTUuNGwuMTE4LS4xMTYtLjExOC0uMTEyWiIgdHJhbnNmb3JtPSJ0cmFuc2xhdGUoMC4wMDUgLTQyLjQ1KSIgb3BhY2l0eT0iMC4xMiIvPgogICAgPC9nPgogICAgPHBhdGggaWQ9IlBhdGhfMTIwOSIgZGF0YS1uYW1lPSJQYXRoIDEyMDkiIGQ9Ik00Ni4yOTIsMzAuODM2LDM4LjQxLDM1LjI0MmwuMTQ5LjE0NSw3LjczMy00LjMyMWEyLjczMiwyLjczMiwwLDAsMCwxLjY1Ny0yLjI0NiwyLjkwNiwyLjkwNiwwLDAsMS0xLjY1NywyLjAxN1oiIHRyYW5zZm9ybT0idHJhbnNsYXRlKC0xMS40NTMgLTguNDk3KSIgb3BhY2l0eT0iMC4xMiIvPgogICAgPHBhdGggaWQ9IlBhdGhfMTIxMCIgZGF0YS1uYW1lPSJQYXRoIDEyMTAiIGQ9Ik00LjAxNiwxLjA3MywzNC44MzcsMTguM2EyLjksMi45LDAsMCwxLDEuNjU3LDIuMDE4LDIuNzMyLDIuNzMyLDAsMCwwLTEuNjU3LTIuMjQ2TDQuMDE2Ljg0N0MxLjgwOS0uMzg4LDAsLjYzOCwwLDMuMTI2di4yMjdDMCwuODY0LDEuODA3LS4xNjEsNC4wMTYsMS4wNzNaIiB0cmFuc2Zvcm09InRyYW5zbGF0ZSgwIDApIiBmaWxsPSIjZmZmIiBvcGFjaXR5PSIwLjI1Ii8+CiAgPC9nPgo8L3N2Zz4K"/></a>
                    </span>
                  </div>
                </div>


              </div>
              <!-- <div class="form-group">
                <h5><span>Or</span></h5>
              </div> -->
              <!-- <div class="form-group">
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
              </div>  -->
            </form>
          </div>
          <!-- <div class="row">
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
          </div> -->
        </b-card>
      </form>
    </div>
    <div class="col-md-4"></div>
    
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
