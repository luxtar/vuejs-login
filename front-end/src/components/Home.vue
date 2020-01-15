<template>
  <div class="container">
    <header class="jumbotron">
       <canvas ref="can" width="1600" height="900"></canvas>
    </header>
  </div>
</template>

<script>
import { fabric } from 'fabric';

export default {
  mounted() {
    const ref = this.$refs.can;
    const canvas = new fabric.Canvas(ref);
    // create a rectangle object
    var rect = new fabric.Rect({
      left: 100,
      top: 50,
      fill: '#D81B60',
      width: 50,
      height: 50,
      strokeWidth: 2,
      stroke: '#880E4F',
      rx: 10,
      ry: 10,
      angle: 45,
      scaleX: 3,
      scaleY: 3,
      hasControls: true
    });

    canvas.add(rect);

    var circle1 = new fabric.Circle({
      radius: 65,
      fill: '#039BE5',
      left: 0,
      stroke: 'red',
      strokeWidth: 3
    });

    var circle2 = new fabric.Circle({
      radius: 65,
      fill: '#4FC3F7',
      left: 110,
      opacity: 0.7,
      stroke: 'blue',
      strokeWidth: 3,
      strokeUniform: true
    });

    canvas.add(circle1);
    canvas.add(circle2);
  }
};
</script>
