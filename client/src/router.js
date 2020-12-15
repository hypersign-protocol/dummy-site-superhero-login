import Vue from 'vue'
import Router from 'vue-router'
import PKIIdLogin from './views/PKIIdLogin.vue'
import Register from './views/Register.vue'
import config from './config'
import Dashboard from './views/Dashboard.vue'
import fetch from 'node-fetch'

Vue.use(Router)

const router = new Router({
    mode: 'history',
    routes: [{
            path: '/login',
            redirect: '/studio/login'
        },
        {
            path: '/studio',
            redirect: '/studio/login'
        },
        {
            path: '/studio/login',
            name: 'PKIIdLogin',
            component: PKIIdLogin
        },
        {
            path: '/studio/dashboard',
            name: 'dashboard',
            component: Dashboard,
            meta: {
                requiresAuth: true
            }
        },
        {
            path: '/studio/register',
            name: 'register',
            component: Register
        },
    ]
})

router.beforeEach((to, from, next) => {
    if (to.matched.some(record => record.meta.requiresAuth)) {
        const authToken = localStorage.getItem('authToken');
        if (authToken) {
            const url = `${config.studioServer.BASE_URL}protected`
            fetch(url, {
                    headers: {
                        "x-auth-token": authToken
                    },
                    method: "POST"
                }).then(res => res.json())
                .then(json => {
                    if (json.status == 403) {
                        next({
                            path: '/studio/login',
                            params: { nextUrl: to.fullPath }
                        })
                    } else {
                        localStorage.setItem("user", JSON.stringify(json.message));
                        next()
                    }
                })
                .catch((e) => {
                    next({
                        path: '/studio/login',
                        params: { nextUrl: to.fullPath }
                    })
                })
        } else {
            next({
                path: '/studio/login',
                params: { nextUrl: to.fullPath }
            })
        }
    } else {
        next()
    }
})
export default router