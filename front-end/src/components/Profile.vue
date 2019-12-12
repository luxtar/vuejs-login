<template>
  <div class="container">
    <header class="jumbotron">
      <h3>user name : {{content.username}}</h3>
      <h3>email : {{content.email}}</h3>
    </header>
  </div>
</template>

<script>
import UserService from '../services/user.service';

export default {
  name: 'profile',
  data() {
    return {
      content: ''
    }
  },
  mounted() {
    UserService.getUserContent().then(
      response => {
        this.content = response.data;
      },
      error => {
        this.content = error.response.data.message;
      }
    )
  }
};
</script>