<template>
  <div class="container">
    <header class="jumbotron">
      <h3>Home content</h3>
    </header>
  </div>
</template>

<script>

fabric.Object.prototype.noScaleCache = false;

export default {
  name: 'Home',
  data() {
    return {
      content: ''
    }
  },
  mounted() {
  }
};
</script>