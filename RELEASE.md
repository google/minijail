# Tagging Minijail releases

* Choose a new-ish, stable-ish commit (i.e. not one that implements a completely
new feature).

* Find the latest tag:
`minijail$ git tag -l "linux-v*"`

* Tag the commit with the next version number:
`minijail$ git tag -a linux-v<N+1> <commit>`

* Push the tag:
`minijail$ git push aosp linux-v<N+1>`

We will tag a new release ~monthly at the beginning of the month.
