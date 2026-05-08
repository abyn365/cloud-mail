import axios from '../axios'

export default {
    list() {
        return axios.get('/merge/list')
    },
    send(data) {
        return axios.post('/merge/send', data)
    }
}
